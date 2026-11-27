//! Read-side commands: find, big, types, sql, stats.

use crate::fmt::{self, Render, Table};
use crate::{db, names};
use anyhow::Result;
use rusqlite::{params_from_iter, types::Value as SqlV, Connection};
use std::path::Path;

/// Run `sql` and collect rows into a table with the given column rendering.
pub fn table(c: &Connection, sql: &str, args: &[SqlV], cols: &[(&str, Render)]) -> Result<Table> {
    let mut t = Table::new(cols);
    let mut st = c.prepare(sql)?;
    let n = st.column_count();
    let mut rows = st.query(params_from_iter(args.iter()))?;
    while let Some(r) = rows.next()? {
        t.rows.push((0..n).map(|i| fmt::sql_value(r.get_ref(i).unwrap())).collect());
    }
    Ok(t)
}

/// Absolute, canonical path prefix for --under.
fn under_arg(u: &Option<String>) -> Result<Option<String>> {
    Ok(u.as_ref().map(|p| std::fs::canonicalize(p).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| p.clone())))
}

/// SQL predicate: dir path `col` equals or is below `?`. Case-sensitive, uses no LIKE.
fn under_pred(col: &str, args: &mut Vec<SqlV>, u: &str) -> String {
    args.push(SqlV::Text(u.to_string()));
    args.push(SqlV::Text(format!("{u}/")));
    args.push(SqlV::Text(format!("{u}0"))); // '0' = '/' + 1
    let n = args.len();
    format!("({col} = ?{} OR ({col} >= ?{} AND {col} < ?{}))", n - 2, n - 1, n)
}

pub struct FindArgs {
    pub terms: Vec<String>,
    pub kind: Option<String>,
    pub ext: Option<String>,
    pub min_size: Option<String>,
    pub under: Option<String>,
    pub dirs: bool,
    pub files: bool,
    pub sort: String,
    pub limit: i64,
}

pub fn find(a: &FindArgs) -> Result<Table> {
    let c = db::open_index()?;
    let t0 = std::time::Instant::now();
    let mut file_ids = vec![];
    let mut dir_ids = vec![];
    let have_terms = !a.terms.is_empty();
    if have_terms {
        let idx = names::Index::open(&db::data_dir())?;
        for id in idx.search(&a.terms) {
            if id > 0 { file_ids.push(id) } else { dir_ids.push(-id) }
        }
        c.execute_batch("CREATE TEMP TABLE cand_f(id INTEGER PRIMARY KEY); CREATE TEMP TABLE cand_d(id INTEGER PRIMARY KEY);")?;
        let tx = c.unchecked_transaction()?;
        {
            let mut i1 = tx.prepare("INSERT INTO cand_f VALUES (?1)")?;
            for id in &file_ids { i1.execute([id])?; }
            let mut i2 = tx.prepare("INSERT INTO cand_d VALUES (?1)")?;
            for id in &dir_ids { i2.execute([id])?; }
        }
        tx.commit()?;
    }
    let t_scan = t0.elapsed();
    let under = under_arg(&a.under)?;
    let order = match a.sort.as_str() {
        "size" => "size DESC",
        "name" => "path",
        _ => "mtime DESC",
    };

    let mut out = Table::new(&[("path", Render::Plain), ("size", Render::Bytes), ("kind", Render::Plain), ("modified", Render::Date)]);
    let want_dirs = !a.files && a.kind.is_none() && a.ext.is_none() && (have_terms || a.dirs);
    let want_files = !a.dirs;

    if want_files {
        let mut args: Vec<SqlV> = vec![];
        let mut w = vec!["1".to_string()];
        if let Some(k) = &a.kind { args.push(SqlV::Text(k.clone())); w.push(format!("f.kind = ?{}", args.len())); }
        if let Some(e) = &a.ext { args.push(SqlV::Text(e.trim_start_matches('.').to_lowercase())); w.push(format!("f.ext = ?{}", args.len())); }
        if let Some(m) = &a.min_size { args.push(SqlV::Integer(fmt::parse_size(m)?)); w.push(format!("f.size >= ?{}", args.len())); }
        if let Some(u) = &under { w.push(under_pred("d.path", &mut args, u)); }
        let from = if have_terms { "cand_f c JOIN files f ON f.id = c.id" } else { "files f" };
        args.push(SqlV::Integer(a.limit));
        let sql = format!(
            "SELECT path, size, kind, mtime FROM (
               SELECT d.path || '/' || f.name AS path, f.size, f.kind, f.mtime
               FROM {from} JOIN dirs d ON d.id = f.dir WHERE {})
             ORDER BY {order} LIMIT ?{}",
            w.join(" AND "), args.len()
        );
        out.rows.extend(table(&c, &sql, &args, &[])?.rows);
    }
    if want_dirs {
        let mut args: Vec<SqlV> = vec![];
        let mut w = vec!["1".to_string()];
        if let Some(m) = &a.min_size { args.push(SqlV::Integer(fmt::parse_size(m)?)); w.push(format!("s.bytes >= ?{}", args.len())); }
        if let Some(u) = &under { w.push(under_pred("d.path", &mut args, u)); }
        let from = if have_terms { "cand_d c JOIN dirs d ON d.id = c.id" } else { "dirs d" };
        args.push(SqlV::Integer(a.limit));
        let sql = format!(
            "SELECT path, size, kind, mtime FROM (
               SELECT d.path || '/' AS path, s.bytes AS size, CASE WHEN d.is_repo THEN 'dir:git' WHEN d.opaque THEN 'dir:opaque' ELSE 'dir' END AS kind, NULL AS mtime
               FROM {from} JOIN dir_stats s ON s.dir = d.id WHERE {})
             ORDER BY {} LIMIT ?{}",
            w.join(" AND "), if a.sort == "name" { "path" } else { "size DESC" }, args.len()
        );
        let mut dirs = table(&c, &sql, &args, &[])?.rows;
        if want_files {
            dirs.truncate(((a.limit / 5).max(3)) as usize); // keep room for files
        }
        out.rows.splice(0..0, dirs);
    }
    out.rows.truncate(a.limit as usize);
    if have_terms {
        out.note = Some(format!(
            "{} shown; name scan matched {} files, {} dirs in {:.0} ms",
            out.rows.len(), file_ids.len(), dir_ids.len(), t_scan.as_secs_f64() * 1000.0
        ));
    }
    Ok(out)
}

pub struct BigArgs {
    pub under: Option<String>,
    pub depth: Option<i64>,
    pub files: bool,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub min_size: String,
    pub limit: i64,
}

/// Large directories / files, straight from dir_stats (precomputed subtree totals).
pub fn big(a: &BigArgs) -> Result<Table> {
    let c = db::open_index()?;
    let under = under_arg(&a.under)?;
    let mut args: Vec<SqlV> = vec![];
    let mut w = vec![];

    if a.files {
        if let Some(u) = &under { w.push(under_pred("d.path", &mut args, u)); }
        if let Some(k) = &a.kind { args.push(SqlV::Text(k.clone())); w.push(format!("f.kind = ?{}", args.len())); }
        w.push("1".into());
        args.push(SqlV::Integer(a.limit));
        let sql = format!(
            "SELECT d.path || '/' || f.name, f.size, f.kind, f.mtime FROM files f JOIN dirs d ON d.id = f.dir
             WHERE {} ORDER BY f.size DESC LIMIT ?{}", w.join(" AND "), args.len());
        return table(&c, &sql, &args, &[("path", Render::Plain), ("size", Render::Bytes), ("kind", Render::Plain), ("modified", Render::Date)]);
    }

    args.push(SqlV::Integer(fmt::parse_size(&a.min_size)?));
    w.push(format!("s.bytes >= ?{}", args.len()));
    let cols = [("path", Render::Plain), ("size", Render::Bytes), ("files", Render::Plain), ("own", Render::Bytes), ("biggest child", Render::Pct), ("type", Render::Plain)];
    let sel = "SELECT d.path, s.bytes, s.files, s.own_bytes, CASE WHEN s.bytes > 0 THEN 100.0 * s.max_child / s.bytes END,
               CASE WHEN d.opaque THEN 'opaque' WHEN d.is_repo THEN 'git' ELSE '' END
               FROM dir_stats s JOIN dirs d ON d.id = s.dir";
    if let Some(n) = &a.name {
        // e.g. --name node_modules: every such dir, biggest first
        args.push(SqlV::Text(n.clone()));
        w.push(format!("d.name = ?{}", args.len()));
        if let Some(u) = &under { w.push(under_pred("d.path", &mut args, u)); }
    } else if let Some(u) = &under {
        // du-like: children (or descendants to --depth) of a directory
        // depth by counting '/' in the path, not dir_stats.depth: iCloud Drive is its own scan
        // root (depth restarts at 0) but lives inside the home folder's path range
        c.query_row("SELECT 1 FROM dirs WHERE path = ?1", [u], |_| Ok(()))
            .map_err(|_| anyhow::anyhow!("{u} is not an indexed directory"))?;
        let base = u.matches('/').count() as i64;
        args.push(SqlV::Integer(base + a.depth.unwrap_or(1)));
        w.push(format!("length(d.path) - length(replace(d.path, '/', '')) <= ?{}", args.len()));
        args.push(SqlV::Text(format!("{u}/")));
        args.push(SqlV::Text(format!("{u}0")));
        w.push(format!("d.path >= ?{} AND d.path < ?{}", args.len() - 1, args.len()));
    } else {
        // "heavy" dirs: size is spread over this dir, not concentrated in one child
        w.push("s.max_child < s.bytes * 0.5".into());
        if let Some(d) = a.depth { args.push(SqlV::Integer(d)); w.push(format!("s.depth <= ?{}", args.len())); }
    }
    args.push(SqlV::Integer(a.limit));
    let sql = format!("{sel} WHERE {} ORDER BY s.bytes DESC LIMIT ?{}", w.join(" AND "), args.len());
    table(&c, &sql, &args, &cols)
}

pub fn types(kind: Option<&str>, by_ext: bool, limit: i64) -> Result<Table> {
    let c = db::open_index()?;
    let cols = [("group", Render::Plain), ("files", Render::Plain), ("size", Render::Bytes), ("largest", Render::Bytes)];
    let t = match (&kind, by_ext) {
        (Some(k), _) => table(&c, "SELECT CASE ext WHEN '' THEN '(none)' ELSE ext END, count(*), sum(size), max(size) FROM files WHERE kind = ?1 GROUP BY ext ORDER BY 3 DESC LIMIT ?2",
            &[SqlV::Text(k.to_string()), SqlV::Integer(limit)], &cols)?,
        (None, true) => table(&c, "SELECT CASE ext WHEN '' THEN '(none)' ELSE ext END, count(*), sum(size), max(size) FROM files GROUP BY ext ORDER BY 3 DESC LIMIT ?1",
            &[SqlV::Integer(limit)], &cols)?,
        (None, false) => table(&c, "SELECT kind, count(*), sum(size), max(size) FROM files GROUP BY kind ORDER BY 3 DESC", &[], &cols)?,
    };
    Ok(t)
}

pub fn sql(q: &str, write: bool) -> Result<Table> {
    let c = db::open_index()?;
    if !write {
        c.execute_batch("PRAGMA query_only = 1;")?;
    }
    let head = q.trim_start().to_lowercase();
    if write && !(head.starts_with("select") || head.starts_with("with") || head.starts_with("pragma")) {
        c.execute_batch(q)?; // DDL/DML, possibly several statements
        return Ok(done(c.changes()));
    }
    let st = c.prepare(q)?;
    // query_only blocks writes to the index, but ATTACH and VACUUM INTO can still create a file elsewhere
    if !write && (!st.readonly() || head.starts_with("attach") || head.starts_with("vacuum")) {
        anyhow::bail!("read-only: only SELECT / WITH / PRAGMA queries (pass --write to change the index)");
    }
    let names: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
    drop(st);
    if names.is_empty() {
        c.execute_batch(q)?;
        return Ok(done(c.changes()));
    }
    // render columns named like sizes/times nicely in text mode
    let cols: Vec<(&str, Render)> = names
        .iter()
        .map(|n| {
            let l = n.to_lowercase();
            let r = if ["size", "bytes", "alloc", "own_bytes", "max_child", "waste", "reclaim"].iter().any(|k| l == *k || l.ends_with(&format!("_{k}")))
                { Render::Bytes } else if l == "mtime" { Render::Date } else { Render::Plain };
            (n.as_str(), r)
        })
        .collect();
    table(&c, q, &[], &cols)
}

fn done(changes: u64) -> Table {
    let mut t = Table::new(&[]);
    t.note = Some(format!("ok, {changes} rows changed"));
    t
}

pub fn stats() -> Result<Table> {
    let c = db::open_index()?;
    let mut t = table(&c, "SELECT key, value FROM meta ORDER BY key", &[], &[("key", Render::Plain), ("value", Render::Plain)])?;
    let q = |s: &str| -> Result<i64> { Ok(c.query_row(s, [], |r| r.get(0))?) };
    let add = |t: &mut Table, k: &str, v: String| t.rows.push(vec![k.into(), v.into()]);
    add(&mut t, "files", q("SELECT count(*) FROM files")?.to_string());
    add(&mut t, "dirs", q("SELECT count(*) FROM dirs")?.to_string());
    add(&mut t, "opaque dirs", q("SELECT count(*) FROM dirs WHERE opaque")?.to_string());
    add(&mut t, "git repos", q("SELECT count(*) FROM dirs WHERE is_repo")?.to_string());
    add(&mut t, "bytes (roots)", fmt::bytes(q("SELECT coalesce(sum(s.bytes),0) FROM dir_stats s JOIN dirs d ON d.id=s.dir WHERE d.parent IS NULL")?));
    add(&mut t, "cached hashes", q("SELECT count(*) FROM cache.hashes")?.to_string());
    let dir = db::data_dir();
    for f in ["index.db", "names.bin", "offsets.bin", "ids.bin", "hashes.db"] {
        if let Ok(m) = std::fs::metadata(Path::new(&dir).join(f)) {
            add(&mut t, f, fmt::bytes(m.len() as i64));
        }
    }
    if let Some(r) = t.rows.iter_mut().find(|r| r[0] == "scanned_at") {
        let s: i64 = r[1].as_str().unwrap_or("0").parse().unwrap_or(0);
        r[1] = fmt::date(s * 1_000_000_000).into();
    }
    Ok(t)
}

pub struct PkgArgs {
    pub name: Option<String>,
    /// a version range ("2.1.0", "2.*", "^2.1", ">=2.1 <2.3", "~=2.1") or "/regex/" (anchored)
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub source: Option<String>,
    pub under: Option<String>,
    /// name must match exactly (pypi names are compared PEP 503-normalised)
    pub exact: bool,
    pub paths: bool,
    pub limit: i64,
}

/// How `-v` is matched.
enum VMode {
    /// a version range (or one version): resolved versions inside it, declared ranges overlapping it
    Range { point: bool },
    Regex,
}

/// SQL functions for the version filter: vmatch(version) and voverlap(ecosystem, range).
/// `-v` is a range (`2.1.0`, `2.*`, `^2.1`, `>=2.1 <2.3`, `~=2.1`) unless it is written `/regex/`
/// or does not parse as a range (then it is an anchored regex too).
fn version_fns(c: &Connection, v: &str) -> Result<VMode> {
    use rusqlite::functions::FunctionFlags;
    let f = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    let slashed = v.len() > 1 && v.starts_with('/') && v.ends_with('/');
    if let Some(q) = (!slashed).then(|| crate::versions::query(v)).flatten() {
        let point = q.is_point();
        let q = std::sync::Arc::new(q);
        let q2 = q.clone();
        c.create_scalar_function("vmatch", 1, f, move |ctx| Ok(q.matches(&ctx.get::<String>(0)?)))?;
        c.create_scalar_function("voverlap", 2, f, move |ctx| {
            Ok(q2.overlaps(&ctx.get::<String>(0)?, &ctx.get::<String>(1)?).map(i64::from))
        })?;
        return Ok(VMode::Range { point });
    }
    let pat = if slashed { &v[1..v.len() - 1] } else { v };
    regex::Regex::new(pat).map_err(|e| anyhow::anyhow!("-v is neither a version range nor a valid regex: {e}"))?;
    let re = regex::Regex::new(&format!("(?i)^(?:v?(?:{pat}))$"))?;
    c.create_scalar_function("vmatch", 1, f, move |ctx| Ok(re.is_match(&ctx.get::<String>(0)?)))?;
    Ok(VMode::Regex)
}

/// Package inventory: summary per ecosystem, versions of matching packages, or every location.
pub fn packages(a: &PkgArgs) -> Result<Table> {
    let c = db::open_index()?;
    let mut args: Vec<SqlV> = vec![];
    let mut w = vec!["1".to_string()];
    if let Some(n) = &a.name {
        let n = n.to_lowercase();
        if a.exact {
            let norm: String = n.split(['_', '.', '-']).filter(|x| !x.is_empty()).collect::<Vec<_>>().join("-");
            args.push(SqlV::Text(n));
            args.push(SqlV::Text(norm));
            w.push(format!("lower(p.name) IN (?{}, ?{})", args.len() - 1, args.len()));
        } else {
            args.push(SqlV::Text(format!("%{n}%")));
            w.push(format!("lower(p.name) LIKE ?{}", args.len()));
        }
    }
    for (col, v) in [("p.ecosystem", &a.ecosystem), ("p.source", &a.source)] {
        if let Some(v) = v {
            args.push(SqlV::Text(v.clone()));
            w.push(format!("{col} = ?{}", args.len()));
        }
    }
    let mut mode = None;
    if let Some(v) = &a.version {
        let m = version_fns(&c, v)?;
        // declared ranges can only be compared with a range, not with a regex
        w.push(match m {
            VMode::Range { .. } => "((p.source <> 'declared' AND vmatch(p.version)) OR (p.source = 'declared' AND voverlap(p.ecosystem, p.version) IS NOT 0))".into(),
            VMode::Regex => "p.source <> 'declared' AND vmatch(p.version)".to_string(),
        });
        mode = Some(m);
    }
    if let Some(u) = under_arg(&a.under)? {
        w.push(under_pred("p.path", &mut args, &u));
    }
    let wh = w.join(" AND ");
    args.push(SqlV::Integer(a.limit));
    let lim = args.len();
    let p = Render::Plain;
    if a.name.is_none() && a.version.is_none() && !a.paths {
        let sql = format!(
            "SELECT p.ecosystem, p.source, count(DISTINCT p.name) , count(DISTINCT p.name || '@' || p.version), count(*), count(DISTINCT p.path)
             FROM packages p WHERE {wh} GROUP BY 1, 2 ORDER BY 5 DESC LIMIT ?{lim}");
        let mut t = table(&c, &sql, &args, &[("ecosystem", p), ("source", p), ("packages", p), ("versions", p), ("rows", p), ("files", p)])?;
        t.note = Some("give a NAME for versions and locations, e.g. `fff packages lodash`; declared = ranges in project files".into());
        return Ok(t);
    }
    if a.paths || a.version.is_some() {
        // where is it: installed copies, lockfile pins, then project files whose range allows it
        let status = match mode {
            Some(VMode::Range { point }) => format!(
                "CASE p.source WHEN 'declared' THEN CASE voverlap(p.ecosystem, p.version) WHEN 1 THEN '{}' ELSE 'declared, range unknown' END ELSE p.source END",
                if point { "declared, allows it" } else { "declared, overlaps" }
            ),
            _ => "p.source".to_string(),
        };
        let sql = format!(
            "SELECT p.ecosystem, p.name, p.version, {status}, p.path FROM packages p WHERE {wh}
             ORDER BY CASE p.source WHEN 'installed' THEN 0 WHEN 'lockfile' THEN 1 ELSE 2 END, p.name, p.version, p.path LIMIT ?{lim}");
        let mut t = table(&c, &sql, &args, &[("ecosystem", p), ("name", p), ("version / range", p), ("status", p), ("path", p)])?;
        let count = |s: &str| t.rows.iter().filter(|r| r[3].as_str().is_some_and(|x| x.starts_with(s))).count();
        let (i, l, d) = (count("installed"), count("lockfile"), count("declared"));
        let mut note = format!("{i} installed, {l} in lockfiles, {d} project files whose range could resolve to it");
        if matches!(mode, Some(VMode::Regex)) {
            note.push_str(" (declared ranges are not compared with a regex; use a range like 2.* or ^2.1)");
        }
        if t.rows.len() as i64 == a.limit {
            note.push_str(&format!("; limited to {} rows, raise with -n", a.limit));
        }
        t.note = Some(note);
        return Ok(t);
    }
    let sql = format!(
        "SELECT p.ecosystem, p.name, p.version, sum(p.source = 'installed'), sum(p.source = 'lockfile'), min(p.path), p.purl
         FROM packages p WHERE {wh} AND p.source <> 'declared' GROUP BY p.ecosystem, p.name, p.version
         ORDER BY p.ecosystem, p.name, p.version LIMIT ?{lim}");
    let mut t = table(&c, &sql, &args, &[("ecosystem", p), ("name", p), ("version", p), ("installed", p), ("in lockfiles", p), ("e.g.", p), ("purl", p)])?;
    let ndecl: i64 = c.query_row(
        &format!("SELECT count(*) FROM packages p WHERE {wh} AND p.source = 'declared'"),
        params_from_iter(&args[..args.len() - 1]),
        |r| r.get(0),
    )?;
    t.note = Some(format!(
        "{} versions; {ndecl} declared ranges in project files; -v VERSION shows where (and which ranges allow it), --paths lists every location",
        t.rows.len()
    ));
    Ok(t)
}

/// One entry of a compromised-package list: name plus listed versions or ranges (empty = any version).
#[derive(Debug, PartialEq)]
pub struct Want {
    pub eco: Option<String>,
    pub name: String,
    pub versions: Vec<String>,
}

/// Parse a pasted advisory list, one package per line (or several per line):
/// `@ctrl/tinycolor@4.1.1`, `name@1.0.1, 1.0.2`, `name: 1.0.1`, `name 1.0.1`, `name,1.0.1` (CSV),
/// `name==1.0.1`, `name >=1.0 <1.3`, `pkg:npm/%40scope/name@1.0.1`, or a bare name (any version).
/// `#` starts a comment. Entries for the same name are merged. Also returns the entries it could not read.
pub fn parse_wants(text: &str) -> (Vec<Want>, Vec<String>) {
    let mut out: Vec<Want> = vec![];
    let mut bad: Vec<String> = vec![];
    let mut push = |w: Want| match out.iter_mut().find(|o| o.name.eq_ignore_ascii_case(&w.name) && o.eco == w.eco) {
        Some(o) => o.versions.extend(w.versions),
        None => out.push(w),
    };
    for raw in text.lines() {
        let Some(line) = clean_line(raw) else { continue };
        // a range ('>=1.0 <1.3', '^2', '1.x || 3.x') belongs to one package: read the line as one entry
        if line.contains(['<', '>', '^', '~', '*', '|']) || line.contains(" - ") {
            match entry(&line) {
                Some(w) => push(w),
                None => bad.push(line),
            }
            continue;
        }
        // otherwise walk the tokens: a version-looking token belongs to the package before it, anything else
        // starts a new package ('debug (4.4.2), chalk (5.6.1)', 'a@1.0.0, 1.0.1, b@2.0.0', 'npm debug 4.4.2')
        let mut toks: Vec<String> = line
            .replace(": ", " ")
            .split([',', ';', ' ', '\t', '(', ')', '[', ']'])
            .map(|t| t.trim_matches(|c: char| c == '`' || c == '"' || c == '\'' || c == ':').to_string())
            .filter(|t| !t.is_empty())
            .collect();
        let eco = match toks.first().map(|t| t.to_ascii_lowercase()).as_deref() {
            Some("npm") => Some("npm"),
            Some("pypi" | "pip") => Some("pypi"),
            Some("cargo" | "crates.io" | "crates") => Some("cargo"),
            Some("go" | "golang") => Some("go"),
            Some("maven") => Some("maven"),
            _ => None,
        };
        if eco.is_some() && toks.len() > 1 {
            toks.remove(0);
        }
        let mut cur: Option<Want> = None;
        for t in toks {
            let version_like = t.trim_start_matches(['v', '=']).starts_with(|c: char| c.is_ascii_digit());
            if let (true, Some(w)) = (version_like, cur.as_mut()) {
                w.versions.push(t.trim_start_matches(['v', '=']).to_string());
            } else if let Some(mut w) = (!version_like).then(|| entry(&t)).flatten() {
                if w.eco.is_none() {
                    w.eco = eco.map(String::from);
                }
                if let Some(c) = cur.replace(w) {
                    push(c);
                }
            } else {
                bad.push(t);
            }
        }
        if let Some(c) = cur {
            push(c);
        }
    }
    for w in &mut out {
        w.versions.sort();
        w.versions.dedup();
    }
    (out, bad)
}

/// Strip list decoration from a pasted line: comments, bullets, numbering, markdown tables and links,
/// smart quotes and dashes. None = nothing left (blank, comment, table separator row).
fn clean_line(raw: &str) -> Option<String> {
    let mut l = raw.split('#').next().unwrap_or("").to_string();
    // [name](https://…) → name
    while let Some(i) = l.find("](") {
        let Some(j) = l[i..].find(')') else { break };
        l.replace_range(i + 1..i + j + 1, "");
    }
    let l: String = l.chars().map(|c| if "[]|“”‘’«»—–→⇒\u{a0}".contains(c) { ' ' } else { c }).collect();
    let mut l = l.trim().trim_start_matches(['-', '*', '•', '+']).trim();
    // "12. name" / "3) name"
    let digits = l.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 && l[digits..].starts_with(['.', ')']) && l[digits + 1..].starts_with(char::is_whitespace) {
        l = l[digits + 1..].trim();
    }
    let l = l.trim_matches(|c: char| c == '`' || c == '"' || c == '\'');
    if l.is_empty() || l.chars().all(|c| c == '-' || c == ':' || c.is_whitespace()) {
        return None;
    }
    Some(l.to_string())
}

fn entry(s: &str) -> Option<Want> {
    let s = s.trim().trim_matches(|c: char| c == '`' || c == '"' || c == '\'' || c == ',');
    if let Some(p) = s.strip_prefix("pkg:") {
        let (ty, rest) = p.split_once('/')?;
        let rest = rest.replace("%40", "@").replace("%2F", "/").replace("%2f", "/");
        let rest = rest.split(['?', '#']).next().unwrap_or("");
        let (path, ver) = match rest.rfind('@').filter(|&i| i > 0) {
            Some(i) => (&rest[..i], vec![rest[i + 1..].to_string()]),
            None => (rest, vec![]),
        };
        let eco = match ty { "npm" => "npm", "pypi" => "pypi", "cargo" => "cargo", "maven" => "maven", "golang" => "go", _ => return None };
        let name = if eco == "maven" { path.replacen('/', ":", 1) } else { path.to_string() };
        return Some(Want { eco: Some(eco.into()), name, versions: ver });
    }
    // the name ends at the first separator; '@' after the first char, ':' only before a digit or space
    let b = s.as_bytes();
    let end = (1..b.len()).find(|&i| match b[i] {
        b'@' | b' ' | b'\t' | b',' | b';' | b'=' | b'<' | b'>' | b'^' | b'~' | b'(' | b'[' | b'`' | b'"' | b'\'' => true,
        b':' => b.get(i + 1).is_none_or(|c| c.is_ascii_digit() || c.is_ascii_whitespace()),
        _ => false,
    }).unwrap_or(b.len());
    let name = s[..end].trim().to_string();
    if name.is_empty() || name.starts_with(|c: char| !(c.is_ascii_alphanumeric() || c == '@' || c == '_')) {
        return None;
    }
    let rest = s[end..].trim_start_matches(['@', ':', ' ', '\t', ',', ';', '`', '"', '\'']).trim();
    let rest = rest.trim_matches(['(', ')', '[', ']']);
    let rest = rest.strip_prefix("==").map(str::trim).unwrap_or(rest);
    let versions = if rest.is_empty() {
        vec![]
    } else if rest.contains(['<', '>', '^', '~', '*', '|']) || rest.contains(" - ") {
        vec![rest.to_string()] // one range
    } else {
        rest.split([',', ';', ' ', '\t', '/']).map(|v| v.trim().trim_start_matches(['v', '='])).filter(|v| !v.is_empty()).map(String::from).collect()
    };
    Some(Want { eco: None, name, versions })
}

/// Incident check: where are these packages installed or pinned, and which project files could
/// install them (declared range overlaps a listed version)?
pub fn check(list: &str, ecosystem: Option<&str>, under: &Option<String>, limit: i64) -> Result<Table> {
    let (wants, bad) = parse_wants(list);
    let wants = &wants[..];
    use crate::versions::{query, Query};
    if wants.is_empty() {
        anyhow::bail!("no packages in the list (expected lines like `@scope/name@1.2.3` or `name 1.2.3, 1.2.4`)");
    }
    let c = db::open_index()?;
    c.execute_batch("CREATE TEMP TABLE want (name TEXT PRIMARY KEY) WITHOUT ROWID")?;
    let norm = |n: &str| n.to_lowercase().split(['_', '.', '-']).filter(|x| !x.is_empty()).collect::<Vec<_>>().join("-");
    {
        let mut ins = c.prepare("INSERT OR IGNORE INTO want VALUES (?1)")?;
        for w in wants {
            for n in [w.name.clone(), w.name.to_lowercase(), norm(&w.name)] {
                ins.execute([n])?;
            }
        }
    }
    let mut args: Vec<SqlV> = vec![];
    let mut wh = vec!["1".to_string()];
    if let Some(e) = ecosystem {
        args.push(SqlV::Text(e.into()));
        wh.push(format!("p.ecosystem = ?{}", args.len()));
    }
    if let Some(u) = under_arg(under)? {
        wh.push(under_pred("p.path", &mut args, &u));
    }
    let sql = format!(
        "SELECT p.ecosystem, p.name, p.version, p.source, p.path FROM packages p JOIN want w ON w.name = p.name WHERE {}",
        wh.join(" AND ")
    );
    // compiled queries per listed version; None = not a version (compare as text)
    let qs: Vec<Vec<(String, Option<Query>)>> =
        wants.iter().map(|w| w.versions.iter().map(|v| (v.clone(), query(v))).collect()).collect();
    let mut st = c.prepare(&sql)?;
    let mut rows = st.query(params_from_iter(&args))?;
    let mut hits: Vec<(u8, [String; 6])> = vec![];
    let mut seen = vec![false; wants.len()];
    let mut present = vec![false; wants.len()];
    while let Some(r) = rows.next()? {
        let (eco, name, ver, src, path): (String, String, String, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
        for (i, w) in wants.iter().enumerate() {
            let same = w.name.eq_ignore_ascii_case(&name) || (eco == "pypi" && norm(&w.name) == name);
            if !same || w.eco.as_ref().is_some_and(|e| *e != eco) {
                continue;
            }
            present[i] = true;
            let (rank, status, listed): (u8, &str, String) = if w.versions.is_empty() {
                let (k, s) = match src.as_str() { "installed" => (0, "installed"), "lockfile" => (1, "lockfile"), _ => (2, "declared") };
                (k, s, "any".into())
            } else if src != "declared" {
                let m: Vec<&str> = qs[i].iter().filter(|(v, q)| {
                    v.trim_start_matches('v') == ver.trim_start_matches('v') || q.as_ref().is_some_and(|q| q.matches(&ver))
                }).map(|(v, _)| v.as_str()).collect();
                if m.is_empty() {
                    continue;
                }
                (if src == "installed" { 0 } else { 1 }, if src == "installed" { "INSTALLED" } else { "LOCKFILE" }, m.join(", "))
            } else {
                let res: Vec<(&str, Option<bool>)> = qs[i].iter().filter_map(|(v, q)| Some((v.as_str(), q.as_ref()?.overlaps(&eco, &ver)))).collect();
                let m: Vec<&str> = res.iter().filter(|x| x.1 == Some(true)).map(|x| x.0).collect();
                if !m.is_empty() {
                    (2, "could install", m.join(", "))
                } else if res.iter().any(|x| x.1.is_none()) || res.is_empty() {
                    (3, "check: not a range", w.versions.join(", "))
                } else {
                    continue;
                }
            };
            seen[i] = true;
            hits.push((rank, [status.into(), eco.clone(), name.clone(), ver.clone(), listed, path.clone()]));
        }
    }
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1[2].cmp(&b.1[2])).then_with(|| a.1[5].cmp(&b.1[5])));
    let cnt: Vec<usize> = (0..4u8).map(|k| hits.iter().filter(|h| h.0 == k).count()).collect();
    let n = |k: u8| cnt[k as usize];
    let p = Render::Plain;
    let mut t = Table::new(&[("status", p), ("ecosystem", p), ("name", p), ("version / range", p), ("listed", p), ("path", p)]);
    let total = hits.len();
    t.rows = hits.into_iter().take(limit as usize).map(|(_, r)| r.into_iter().map(serde_json::Value::from).collect()).collect();
    let when: i64 = c.query_row("SELECT value FROM meta WHERE key = 'scanned_at'", [], |r| r.get::<_, String>(0)).ok()
        .and_then(|s| s.parse().ok()).unwrap_or(0);
    let hit = seen.iter().filter(|x| **x).count();
    let other = present.iter().zip(&seen).filter(|(p, s)| **p && !**s).count();
    let mut note = format!(
        "{} installed, {} in lockfiles, {} project ranges could install a listed version, {} unclear (tags/urls). \
         {hit} of {} listed packages hit; {other} more are present only at other versions; {} not present at all",
        n(0), n(1), n(2), n(3), wants.len(), wants.len() - hit - other
    );
    if total > limit as usize {
        note.push_str(&format!("; showing {limit} of {total} rows, raise with -n"));
    }
    if !bad.is_empty() {
        let shown: Vec<&str> = bad.iter().take(5).map(String::as_str).collect();
        note.push_str(&format!(". NOT CHECKED, could not read {} entries: {}{}", bad.len(), shown.join(" | "), if bad.len() > 5 { " …" } else { "" }));
    }
    let system: i64 = c.query_row("SELECT count(*) FROM packages WHERE dir IS NULL", [], |r| r.get(0)).unwrap_or(0);
    note.push_str(&format!(
        ". As of the scan at {}; {}not covered: the npm cache (~/.npm), local file:/link: packages, build.gradle without a lockfile, conda, Go binaries, apps",
        fmt::date(when * 1_000_000_000),
        if system > 0 { "includes Homebrew and global npm/pip installs; " } else { "Homebrew / global installs NOT included (scan without explicit roots); " }
    ));
    t.note = Some(note);
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::{parse_wants, Want};
    fn w(eco: Option<&str>, n: &str, v: &[&str]) -> Want {
        Want { eco: eco.map(String::from), name: n.into(), versions: v.iter().map(|s| s.to_string()).collect() }
    }
    #[test]
    fn wants() {
        let t = "# shai-hulud\n@ctrl/tinycolor@4.1.1, 4.1.2\nangulartics2@14.1.2\n- `ngx-toastr` (19.0.1, 19.0.2)\n\
                 left-pad\nrequests==2.31.0\nfoo,1.0.0\npkg:npm/%40nativescript-community/ui-material-core@7.2.49\n\
                 a@1.0.0 b@2.0.0\nbar >=1.0 <1.3\n@ctrl/tinycolor@4.1.1\norg.foo:bar:1.2.3";
        assert_eq!(parse_wants(t).0, vec![
            w(None, "@ctrl/tinycolor", &["4.1.1", "4.1.2"]),
            w(None, "angulartics2", &["14.1.2"]),
            w(None, "ngx-toastr", &["19.0.1", "19.0.2"]),
            w(None, "left-pad", &[]),
            w(None, "requests", &["2.31.0"]),
            w(None, "foo", &["1.0.0"]),
            w(Some("npm"), "@nativescript-community/ui-material-core", &["7.2.49"]),
            w(None, "a", &["1.0.0"]),
            w(None, "b", &["2.0.0"]),
            w(None, "bar", &[">=1.0 <1.3"]),
            w(None, "org.foo:bar", &["1.2.3"]),
        ]);
        // advisory formats seen in the wild: parentheses, colons, bare follow-up versions, numbering,
        // ecosystem columns, markdown tables and links, em dashes and smart quotes
        let t = "debug (4.4.2), chalk (5.6.1)\nx: 1.0.0, y: 2.0.0\np@1.0.0, 1.0.1, q@2.0.0\n2. r 3.0.0\n\
                 npm\ts\t4.0.0\n| t | 5.0.0 |\n|---|---|\n[u](https://example.com/u) 6.0.0\nv — 7.0.0\n“w” 8.0.0";
        let (got, bad) = parse_wants(t);
        assert_eq!(got, vec![
            w(None, "debug", &["4.4.2"]),
            w(None, "chalk", &["5.6.1"]),
            w(None, "x", &["1.0.0"]),
            w(None, "y", &["2.0.0"]),
            w(None, "p", &["1.0.0", "1.0.1"]),
            w(None, "q", &["2.0.0"]),
            w(None, "r", &["3.0.0"]),
            w(Some("npm"), "s", &["4.0.0"]),
            w(None, "t", &["5.0.0"]),
            w(None, "u", &["6.0.0"]),
            w(None, "v", &["7.0.0"]),
            w(None, "w", &["8.0.0"]),
        ]);
        assert!(bad.is_empty(), "{bad:?}");
    }
}
