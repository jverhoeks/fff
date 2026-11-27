//! Built-in MCP server: `fff mcp` speaks JSON-RPC 2.0 over stdio
//! (newline-delimited, MCP "stdio" transport). Stdout carries protocol only;
//! progress goes to stderr. No SDK: the protocol surface we need is small.

use crate::{db, dups, query, scan};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2025-06-18";
const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "fff is a local index of this Mac's files (names, sizes, kinds, \
directory subtree totals, duplicates, installed package versions). Answer questions about where files are and where disk space goes. \
Prefer the specific tools (find, big, types, dups) and fall back to `sql` for anything else; call `schema` \
before writing SQL. Sizes come as bytes plus a *_human twin. If a tool says there is no index, call `scan` \
(takes about 2-6 minutes). Results reflect the last scan (see `stats`). Tools never modify or delete user files.";

fn tools() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    json!([
      {"name": "find",
       "description": "Find files and directories whose NAME contains all terms (case-insensitive substring; ~20 ms over millions of names). With no terms, filters alone list files (e.g. kind=slides sorted by size).",
       "inputSchema": {"type": "object", "properties": {
         "terms": {"type": "array", "items": {"type": "string"}, "description": "Substrings that must all occur in the name"},
         "kind": s("document|slides|sheet|image|video|audio|archive|diskimage|code|data|font|binary|ebook|mail|symlink|other"),
         "ext": s("Extension without dot, e.g. pdf"),
         "min_size": s("e.g. 10M, 1.5G"),
         "under": s("Absolute directory; only results below it"),
         "dirs": b("Only directories"), "files": b("Only files"),
         "sort": s("mtime (default) | size | name"),
         "limit": i("Max rows, default 30")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "big",
       "description": "Where disk space goes, from precomputed directory subtree totals. Default: 'heavy' dirs (no single child holds >=50% of the bytes). under=DIR: du-like children of DIR. name=node_modules: every dir with that name. files=true: largest files.",
       "inputSchema": {"type": "object", "properties": {
         "under": s("Absolute directory for du-like listing"), "depth": i("Levels below `under` (default 1)"),
         "name": s("Directory name, e.g. node_modules, target, .venv"),
         "files": b("Largest files instead of dirs"), "kind": s("With files=true: only this kind"),
         "min_size": s("Default 100M"), "limit": i("Default 30")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "types",
       "description": "File count and bytes per kind, per extension (by_ext), or per extension within one kind.",
       "inputSchema": {"type": "object", "properties": {"kind": s("Break this kind down by extension"), "by_ext": b("Group by extension"), "limit": i("Default 40")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "dups",
       "description": "Find duplicate files by content (size, then partial and full BLAKE3), APFS-clone aware: 'reclaimable' is space actually freed. Cached hashes make re-runs fast; first run can take minutes. Results also go to the dup_files table for sql.",
       "inputSchema": {"type": "object", "properties": {"min_size": s("Default 1M"), "include_caches": b("Include */.cache/*, */Caches/*"), "limit": i("Groups, default 15")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "packages",
       "description": "Package inventory for CVE / version questions: installed packages (node_modules, .venv/site-packages, ~/.m2, Gradle cache, cargo registry, Go module cache, Homebrew, global npm/pip, cargo install), lockfile pins (package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, poetry.lock, uv.lock, go.mod, gradle.lockfile, requirements*.txt) and declared ranges in project files (requirements, pyproject.toml, package.json, Cargo.toml, pom.xml, libs.versions.toml). No name: summary per ecosystem. With name: one row per resolved version with counts plus a purl. With version (or range like 2.*): every location (installed, lockfile, and project files whose declared range overlaps it). paths=true: every location.",
       "inputSchema": {"type": "object", "properties": {
         "name": s("Substring of the package name (npm: @scope/name, pypi: normalised, maven: group:artifact)"),
         "version": s("Version or range: 2.1.0, 2.*, ^2.1, ~2.1, >=2.1 <2.3, 1.x || 3.x, ~=2.1. Also returns project files whose declared range overlaps it. /regex/ for a regex"),
         "exact": b("Exact name match (pypi PEP 503-normalised), e.g. pandas but not geopandas"),
         "ecosystem": s("npm | pypi | maven | cargo | go | brew"),
         "source": s("installed | lockfile | declared"), "under": s("Absolute directory"),
         "paths": b("One row per location"), "limit": i("Default 50")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "repos",
       "description": "Git repositories on this Mac (read from .git at scan time): path, kind (repo/vendored/worktree/submodule), remote, branch, head commit, last activity, size, and \"local work\": what deleting the checkout would lose (live worktrees that depend on it, unpushed branches, stashes, staged changes, edited tracked files; untracked files NOT checked; \"no sign of local work\" / \"unknown (…)\"). dups=true groups duplicate checkouts of the same remote (normalised URL), biggest waste first. no_remote=true: local-only repos.",
       "inputSchema": {"type": "object", "properties": {
         "name": s("Substring of path or remote, e.g. github.com/org/repo"), "dups": b("Duplicate checkouts"),
         "no_remote": b("Only repos without a remote"), "vendored": b("With dups: include vendored clones inside another repo's hidden tool dir (.external_modules …)"), "under": s("Absolute directory"),
         "sort": s("activity (default) | size | junk (rebuildable build/deps bytes) | path"), "limit": i("Default 50")}},
       "annotations": {"readOnlyHint": true}},
      {"name": "check_packages",
       "description": "Incident check for a supply-chain attack (e.g. a worm like Shai-Hulud): given the advisory's list of compromised packages/versions, return where each is INSTALLED (node_modules, site-packages, ...), PINNED in a lockfile, or could be installed because a project's declared range allows a listed version. Paste the list as-is.",
       "inputSchema": {"type": "object", "properties": {
         "packages": {"type": "array", "items": {"type": "string"}, "description": "Entries like '@ctrl/tinycolor@4.1.1', 'name 1.0.1, 1.0.2', 'requests==2.31.0', 'pkg:npm/...@1.0.0', or a bare name for any version. One string with newlines also works"},
         "ecosystem": s("npm | pypi | maven | cargo | go | brew (default any)"), "under": s("Absolute directory"), "limit": i("Default 500")},
         "required": ["packages"]},
       "annotations": {"readOnlyHint": true}},
      {"name": "sql",
       "description": "Read-only SQLite query against the index. Call `schema` first. Use v_files (has full path) and v_dirs (dirs + subtree totals). Path-prefix filter: path >= '/x/' AND path < '/x0'. mtime is ns since epoch.",
       "inputSchema": {"type": "object", "properties": {"query": s("One SELECT statement; add a LIMIT")}, "required": ["query"]},
       "annotations": {"readOnlyHint": true}},
      {"name": "schema", "description": "Tables, columns and views of the index, with notes for writing SQL.",
       "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": true}},
      {"name": "stats", "description": "Index summary: roots, scan time, counts, sizes.",
       "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": true}},
      {"name": "scan",
       "description": "Rebuild the index (about 2-6 minutes for a home folder). Only reads metadata. Default root: home folder plus iCloud Drive, without the rest of ~/Library.",
       "inputSchema": {"type": "object", "properties": {
         "roots": {"type": "array", "items": {"type": "string"}, "description": "Absolute directories, default home"},
         "library": b("Include all of ~/Library"), "full": b("Index inside node_modules, caches, .venv")}},
       "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}}
    ])
}

fn str_arg(a: &Value, k: &str) -> Option<String> {
    a.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from)
}
fn int_arg(a: &Value, k: &str, d: i64) -> i64 {
    a.get(k).and_then(|v| v.as_i64()).unwrap_or(d)
}
fn bool_arg(a: &Value, k: &str) -> bool {
    a.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn table_result(t: crate::fmt::Table) -> Value {
    let mut o = json!({"rows": t.to_json(true), "count": t.rows.len()});
    if let Some(n) = t.note {
        o["note"] = n.into();
    }
    o
}

fn call(name: &str, a: &Value) -> Result<Value> {
    Ok(match name {
        "find" => table_result(query::find(&query::FindArgs {
            terms: a.get("terms").and_then(|v| v.as_array()).map(|v| v.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .or_else(|| str_arg(a, "terms").map(|s| s.split_whitespace().map(String::from).collect()))
                .unwrap_or_default(),
            kind: str_arg(a, "kind"),
            ext: str_arg(a, "ext"),
            min_size: str_arg(a, "min_size"),
            under: str_arg(a, "under"),
            dirs: bool_arg(a, "dirs"),
            files: bool_arg(a, "files"),
            sort: str_arg(a, "sort").unwrap_or_else(|| "mtime".into()),
            limit: int_arg(a, "limit", 30).clamp(1, 1000),
        })?),
        "big" => table_result(query::big(&query::BigArgs {
            under: str_arg(a, "under"),
            depth: a.get("depth").and_then(|v| v.as_i64()),
            files: bool_arg(a, "files"),
            name: str_arg(a, "name"),
            kind: str_arg(a, "kind"),
            min_size: str_arg(a, "min_size").unwrap_or_else(|| "100M".into()),
            limit: int_arg(a, "limit", 30).clamp(1, 1000),
        })?),
        "types" => table_result(query::types(str_arg(a, "kind").as_deref(), bool_arg(a, "by_ext"), int_arg(a, "limit", 40))?),
        "dups" => table_result(dups::run(&dups::Args {
            min_size: str_arg(a, "min_size").unwrap_or_else(|| "1M".into()),
            include_caches: bool_arg(a, "include_caches"),
            limit: int_arg(a, "limit", 15).clamp(1, 500) as usize,
            threads: crate::default_threads(1),
            max_paths: 10,
        })?),
        "packages" => table_result(query::packages(&query::PkgArgs {
            name: str_arg(a, "name"),
            version: str_arg(a, "version"),
            ecosystem: str_arg(a, "ecosystem"),
            source: str_arg(a, "source"),
            under: str_arg(a, "under"),
            exact: bool_arg(a, "exact"),
            paths: bool_arg(a, "paths"),
            limit: int_arg(a, "limit", 50).clamp(1, 1000),
        })?),
        "repos" => table_result(crate::repos::query(&crate::repos::RepoArgs {
            name: str_arg(a, "name"),
            under: str_arg(a, "under"),
            dups: bool_arg(a, "dups"),
            no_remote: bool_arg(a, "no_remote"),
            vendored: bool_arg(a, "vendored"),
            sort: str_arg(a, "sort").unwrap_or_else(|| "activity".into()),
            limit: int_arg(a, "limit", 50).clamp(1, 1000),
        })?),
        "check_packages" => {
            let text = match a.get("packages") {
                Some(Value::Array(v)) => v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("\n"),
                Some(Value::String(s)) => s.clone(),
                _ => return Err(anyhow!("packages is required")),
            };
            table_result(query::check(&text, str_arg(a, "ecosystem").as_deref(), &str_arg(a, "under"), int_arg(a, "limit", 500).clamp(1, 5000))?)
        }
        "sql" => {
            let q = str_arg(a, "query").ok_or_else(|| anyhow!("query is required"))?;
            let mut t = query::sql(&q, false)?;
            if t.rows.len() > 500 {
                let n = t.rows.len();
                t.rows.truncate(500);
                t.note = Some(format!("truncated to 500 of {n} rows; add a LIMIT or aggregate"));
            }
            table_result(t)
        }
        "schema" => json!({"schema": db::schema_doc()}),
        "stats" => table_result(query::stats()?),
        "scan" => {
            let roots: Vec<std::path::PathBuf> = a.get("roots").and_then(|v| v.as_array())
                .map(|v| v.iter().filter_map(|x| x.as_str().map(Into::into)).collect()).unwrap_or_default();
            let summary = scan::run(scan::Options::from_cli(roots, vec![], bool_arg(a, "library"), false, false, bool_arg(a, "full"), false, crate::default_threads(2))?)?;
            json!({"summary": summary})
        }
        _ => return Err(anyhow!("unknown tool {name}")),
    })
}

fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let id = id?; // notifications (no id) get no response
    let result: std::result::Result<Value, (i64, String)> = match method {
        "initialize" => {
            // answer with the client's version when we speak it, else ours (the client then decides)
            let v = params.get("protocolVersion").and_then(|v| v.as_str()).filter(|v| SUPPORTED.contains(v)).unwrap_or(PROTOCOL).to_string();
            Ok(json!({
                "protocolVersion": v,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "fff", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let t0 = std::time::Instant::now();
            let r = call(name, &args);
            eprintln!("fff mcp: {name} {:.0} ms", t0.elapsed().as_secs_f64() * 1000.0);
            Ok(match r {
                Ok(v) => json!({"content": [{"type": "text", "text": serde_json::to_string(&v).unwrap()}], "structuredContent": v, "isError": false}),
                Err(e) => json!({"content": [{"type": "text", "text": format!("error: {e:#}")}], "isError": true}),
            })
        }
        "resources/list" => Ok(json!({"resources": []})),
        "prompts/list" => Ok(json!({"prompts": []})),
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, msg)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}),
    })
}

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) if batch.is_empty() => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "empty batch"}})),
            Ok(Value::Array(batch)) => {
                let rs: Vec<Value> = batch.iter().filter_map(handle).collect();
                if rs.is_empty() { None } else { Some(Value::Array(rs)) }
            }
            Ok(req) => handle(&req),
            Err(e) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}})),
        };
        if let Some(r) = resp {
            writeln!(out, "{}", serde_json::to_string(&r)?)?;
            out.flush()?;
        }
    }
    Ok(())
}
