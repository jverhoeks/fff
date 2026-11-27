//! Git repositories: filled at the end of scan from `dirs.is_repo`, by reading `.git/HEAD`,
//! `.git/config` and refs directly (no git binary, never any network). Duplicate checkouts are
//! repos whose remote URL is the same after normalising (ssh / https / scp forms, `.git` suffix).

use crate::fmt::{Render, Table};
use crate::db;
use anyhow::Result;
use rayon::prelude::*;
use rusqlite::{params, params_from_iter, types::Value as SqlV, Connection};
use std::os::macos::fs::MetadataExt;
use std::path::{Path, PathBuf};

const DATALESS: u32 = 0x4000_0000;

#[derive(Default)]
struct Repo {
    kind: &'static str, // repo | vendored | worktree | submodule
    remote: Option<String>,
    key: Option<String>,
    branch: Option<String>,
    head: Option<String>,
    main: Option<String>, // worktree / submodule: the repository whose objects it uses
    activity: i64,        // ns: newest of .git/index, logs/HEAD, HEAD
}

/// Read a small file unless it is an iCloud placeholder (reading would download it).
fn read(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if m.st_flags() & DATALESS != 0 || m.len() > 4 << 20 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn mtime(p: &Path) -> i64 {
    std::fs::metadata(p).map(|m| m.st_mtime() * 1_000_000_000 + m.st_mtime_nsec()).unwrap_or(0)
}

/// Remote URL without credentials: https://user:token@host/x → https://host/x
pub fn strip_auth(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        // the authority ends at the first '/' after the userinfo's '@'; a raw password may itself hold a '/'
        let end = match rest.rfind('@') {
            Some(i) if !rest[..i].contains('/') || rest[..i].contains(':') => i + 1 + rest[i + 1..].find('/').unwrap_or(rest.len() - i - 1),
            _ => rest.find('/').unwrap_or(rest.len()),
        };
        let (auth, path) = (&rest[..end], rest.get(end + 1..).unwrap_or(""));
        let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        // keep ssh's conventional user (git@), drop anything with a secret
        let user = auth.rsplit_once('@').map(|(u, _)| u).filter(|u| !u.contains(':') && scheme.starts_with("ssh"));
        return match user {
            Some(u) => format!("{scheme}://{u}@{host}/{path}"),
            None => format!("{scheme}://{host}/{path}"),
        };
    }
    url.to_string()
}

/// host/owner/name, lowercase: git@github.com:a/b.git, https://github.com/a/b, ssh://git@github.com:22/a/b → github.com/a/b
pub fn normalize(url: &str) -> Option<String> {
    let clean = strip_auth(url.trim());
    let u = clean.as_str();
    let (host, path) = if let Some((_, rest)) = u.split_once("://") {
        let (auth, path) = rest.split_once('/')?;
        let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        (host.split(':').next()?.to_string(), path.to_string())
    } else if let Some((left, path)) = u.split_once(':').filter(|(l, _)| !l.contains('/')) {
        let host = left.rsplit_once('@').map_or(left, |(_, h)| h);
        (host.to_string(), path.to_string())
    } else {
        // a local path remote
        return Some(format!("file:{}", u.trim_end_matches('/').trim_end_matches(".git")));
    };
    let path = path.trim_matches('/').trim_end_matches(".git").trim_end_matches('/');
    let host = host.to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    // ssh.dev.azure.com:v3/org/project/repo ≡ dev.azure.com/org/project/_git/repo
    let (host, path) = if host == "ssh.dev.azure.com" {
        let p: Vec<&str> = path.trim_start_matches("v3/").split('/').collect();
        if p.len() == 3 { ("dev.azure.com".to_string(), format!("{}/{}/_git/{}", p[0], p[1], p[2])) } else { (host.to_string(), path.to_string()) }
    } else {
        (host.to_string(), path.to_string())
    };
    if path.is_empty() {
        return None;
    }
    Some(format!("{host}/{}", path.to_lowercase()))
}

/// [remote "origin"] url, else the first remote's url.
fn remote_url(config: &str) -> Option<String> {
    let mut cur: Option<String> = None;
    let mut first: Option<String> = None;
    for line in config.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            cur = l.strip_prefix("[remote \"").and_then(|r| r.strip_suffix("\"]")).map(String::from);
        } else if let (Some(name), Some((k, v))) = (&cur, l.split_once('='))
            && k.trim() == "url" {
                let v = v.trim().to_string();
                if name == "origin" {
                    return Some(v);
                }
                first.get_or_insert(v);
            }
    }
    first
}

fn resolve_ref(gitdir: &Path, common: &Path, r: &str) -> Option<String> {
    for d in [gitdir, common] {
        if let Some(s) = read(&d.join(r)) {
            return Some(s.trim().to_string());
        }
    }
    let packed = read(&common.join("packed-refs"))?;
    packed.lines().find_map(|l| l.split_once(' ').filter(|(_, n)| *n == r).map(|(h, _)| h.to_string()))
}

fn inspect(path: &str) -> Option<Repo> {
    let dot = Path::new(path).join(".git");
    let m = std::fs::symlink_metadata(&dot).ok()?;
    let mut r = Repo { kind: "repo", ..Default::default() };
    let gitdir: PathBuf = if m.is_dir() {
        dot.clone()
    } else {
        let s = read(&dot)?;
        let g = s.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
        let g = Path::new(path).join(g); // relative or absolute
        r.kind = if crate::gitstate::is_worktree_gitdir(&g) { "worktree" } else { "submodule" };
        g
    };
    let common = match read(&gitdir.join("commondir")) {
        Some(c) => gitdir.join(c.trim()),
        None => gitdir.clone(),
    };
    let common = common.canonicalize().unwrap_or(common);
    if r.kind != "repo" {
        // …/main/.git/worktrees/x → …/main ; …/super/.git/modules/x → …/super (submodule's parent)
        let base = if r.kind == "worktree" { common.clone() } else { gitdir.clone() };
        r.main = base.ancestors().find(|a| a.file_name().is_some_and(|n| n == ".git")).and_then(|g| g.parent()).map(|p| p.to_string_lossy().into_owned());
    }
    if let Some(head) = read(&gitdir.join("HEAD")) {
        let head = head.trim();
        if let Some(rf) = head.strip_prefix("ref:") {
            let rf = rf.trim();
            r.branch = Some(rf.strip_prefix("refs/heads/").unwrap_or(rf).to_string());
            r.head = resolve_ref(&gitdir, &common, rf);
        } else {
            r.head = Some(head.to_string());
        }
    }
    let config = read(&common.join("config")).or_else(|| read(&gitdir.join("config")));
    if let Some(u) = config.as_deref().and_then(remote_url) {
        r.key = normalize(&u);
        r.remote = Some(strip_auth(&u));
    }
    r.activity = [gitdir.join("index"), gitdir.join("logs/HEAD"), gitdir.join("HEAD")].iter().map(|p| mtime(p)).max().unwrap_or(0);
    Some(r)
}

/// A clone inside another repo under a hidden dir (`.external_modules`, `.terraform`, `.work` …) is tool-managed.
/// Plain sub-folders (a workspace repo holding many clones, `cache/repos/…`) stay real repos: they still cost disk.
fn vendored(outer: &str, path: &str) -> bool {
    path.strip_prefix(outer).is_some_and(|rel| rel.split('/').any(|c| c.starts_with('.')))
}

/// Fill `repos` from the dirs flagged is_repo. Returns the number of repos.
pub fn build(conn: &Connection, threads: usize) -> Result<usize> {
    // the enclosing repo's path, if this clone sits inside another repo's working tree
    let dirs: Vec<(i64, String, Option<String>)> = conn
        .prepare(
            "SELECT d.id, d.path, o.path FROM dirs d LEFT JOIN dirs p ON p.id = d.parent LEFT JOIN dirs o ON o.id = p.repo_root
             WHERE d.is_repo",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
    let found: Vec<(i64, &String, Repo)> = pool.install(|| {
        dirs.par_iter()
            .filter_map(|(id, p, outer)| {
                let mut r = inspect(p)?;
                if r.kind == "repo" && outer.as_deref().is_some_and(|o| vendored(o, p)) {
                    r.kind = "vendored";
                }
                Some((*id, p, r))
            })
            .collect()
    });
    let mut ins = conn.prepare(
        "INSERT INTO repos (dir, path, kind, remote, remote_key, branch, head, main, activity, worktrees, unpushed, stash, changed, at_risk, risk)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
    )?;
    let mut files = conn.prepare("SELECT d.path, f.name, f.mtime, f.size FROM dirs d JOIN files f ON f.dir = d.id WHERE d.repo_root = ?1")?;
    let mut subdirs = conn.prepare("SELECT path, opaque, repo_root FROM dirs WHERE path >= ?1 AND path < ?2")?;
    // loading the per-repo file maps needs the connection (sequential, ~0.3 s); reading .git is I/O, so run that in parallel
    let maps = found.iter().map(|(id, p, _)| load(&mut files, &mut subdirs, *id, p)).collect::<Result<Vec<_>>>()?;
    let states: Vec<_> = pool.install(|| found.par_iter().zip(maps).map(|((_, p, _), m)| state(p, &m)).collect());
    for ((id, p, r), st) in found.iter().zip(states) {
        let (wt, up, stash, changed, risk, at) = match &st {
            Some(s) => {
                let at = if !s.risks().is_empty() { Some(1) } else if s.unknown.is_empty() && s.changed.is_some() { Some(0) } else { None };
                (Some(s.worktrees.len() as i64), Some(s.unpushed.len() as i64), Some(s.stash as i64), s.changed.map(|n| n as i64), Some(s.verdict()), at)
            }
            None => (None, None, None, None, Some("unknown (unreadable .git)".to_string()), None),
        };
        ins.execute(params![id, p, r.kind, r.remote, r.key, r.branch, r.head, r.main, r.activity, wt, up, stash, changed, at, risk])?;
    }
    Ok(found.len())
}

/// a checkout's files as the index saw them (rel path → mtime, size), and its dirs: walked (true) or
/// opaque / another repo's (false). Tracked files under the latter were never stat'ed, so they are skipped.
struct Seen {
    files: std::collections::HashMap<String, (i64, u64)>,
    walked: std::collections::HashMap<String, bool>,
}

fn load(files: &mut rusqlite::Statement, subdirs: &mut rusqlite::Statement, id: i64, path: &str) -> Result<Seen> {
    let pre = format!("{path}/");
    let mut seen = Seen { files: Default::default(), walked: Default::default() };
    for row in files.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))? {
        let (d, n, m, s) = row?;
        let rel = if d == path { n } else { format!("{}/{n}", d.strip_prefix(&pre).unwrap_or(&d)) };
        seen.files.insert(rel, (m, s as u64));
    }
    for row in subdirs.query_map([pre.clone(), format!("{path}0")], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?, r.get::<_, Option<i64>>(2)?)))? {
        let (d, opaque, root) = row?;
        seen.walked.insert(d[pre.len()..].to_string(), !opaque && root == Some(id));
    }
    Ok(seen)
}

/// gitstate for one checkout, with file stats from the index instead of lstat
fn state(path: &str, m: &Seen) -> Option<crate::gitstate::State> {
    use crate::gitstate::Seen as S;
    let stat = |rel: &str| -> S {
        if let Some((t, s)) = m.files.get(rel) {
            return S::File(*t, *s);
        }
        // nearest ancestor dir we know about decides: walked → the file is gone; opaque/nested → unknowable
        let mut a = rel;
        while let Some((parent, _)) = a.rsplit_once('/') {
            if let Some(w) = m.walked.get(parent) {
                // inside an unindexed dir (.cargo, .yarn/releases, .gradle … can be committed): lstat it now
                return if *w { S::Missing } else { crate::gitstate::live_stat(Path::new(path))(rel) };
            }
            a = parent;
        }
        S::Missing // top-level file of the checkout, not on disk
    };
    crate::gitstate::read_state(Path::new(path), &stat)
}

pub struct RepoArgs {
    /// substring of path or remote
    pub name: Option<String>,
    pub under: Option<String>,
    /// group checkouts of the same remote
    pub dups: bool,
    /// only repos without a remote (work that exists nowhere else)
    pub no_remote: bool,
    /// include vendored clones (inside another repo's hidden tool dir) in --dups
    pub vendored: bool,
    /// activity | size | junk (build/deps bytes) | path
    pub sort: String,
    pub limit: i64,
}

pub fn query(a: &RepoArgs) -> Result<Table> {
    let c = db::open_index()?;
    let mut args: Vec<SqlV> = vec![];
    let mut w = vec!["1".to_string()];
    if let Some(n) = &a.name {
        args.push(SqlV::Text(format!("%{}%", n.to_lowercase())));
        w.push(format!("(lower(r.path) LIKE ?{0} OR r.remote_key LIKE ?{0})", args.len()));
    }
    if let Some(u) = &a.under {
        let u = std::fs::canonicalize(u).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| u.clone());
        for x in [u.clone(), format!("{u}/"), format!("{u}0")] {
            args.push(SqlV::Text(x));
        }
        let n = args.len();
        w.push(format!("(r.path = ?{} OR (r.path >= ?{} AND r.path < ?{}))", n - 2, n - 1, n));
    }
    if a.no_remote {
        w.push("r.remote IS NULL".into());
    }
    let wh = w.join(" AND ");
    let p = Render::Plain;
    // bytes in a repo's opaque dirs other than .git: target/, node_modules, .venv, .next … (rebuildable)
    const JUNK: &str = "LEFT JOIN (SELECT d.repo_root, sum(ds.bytes) junk FROM dirs d JOIN dir_stats ds ON ds.dir = d.id
                         WHERE d.opaque AND d.name <> '.git' GROUP BY d.repo_root) j ON j.repo_root = r.dir";
    let order = match a.sort.as_str() {
        "size" => "s.bytes DESC",
        "junk" => "j.junk DESC",
        "path" => "r.path",
        _ => "r.activity DESC",
    };
    args.push(SqlV::Integer(a.limit));
    let lim = args.len();
    if a.dups {
        // every checkout of a remote that is checked out more than once (worktrees included, marked)
        let vend = if a.vendored { "1" } else { "r.kind <> 'vendored'" };
        let sql = format!(
            "WITH m AS (SELECT r.*, s.bytes, coalesce(j.junk, 0) junk FROM repos r JOIN dir_stats s ON s.dir = r.dir {JUNK}
                        WHERE {wh} AND r.remote_key IS NOT NULL AND {vend}),
                  g AS (SELECT remote_key, count(*) n, sum(bytes) total, max(bytes) biggest FROM m GROUP BY remote_key HAVING count(*) > 1)
             SELECT m.remote_key, g.n, m.kind, m.path, m.branch, substr(m.head, 1, 10), m.activity, m.bytes, m.junk, coalesce(m.risk, '')
             FROM m JOIN g USING (remote_key)
             ORDER BY g.total - g.biggest DESC, m.remote_key, m.kind <> 'repo', m.activity DESC LIMIT ?{lim}");
        let mut t = crate::query::table(&c, &sql, &args, &[("remote", p), ("copies", p), ("kind", p), ("path", p), ("branch", p),
            ("head", p), ("last activity", Render::Date), ("size", Render::Bytes), ("build/deps", Render::Bytes), ("local work", p)])?;
        // full top-level clones (kind = repo) are the real duplicates; worktrees are deliberate, but their build
        // output adds up; vendored clones (in another repo's hidden tool dir) are tool-managed
        type Sums = (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64);
        let (groups, copies, extra, nwt, wt_bytes, wt_junk, nv, v_bytes, nclean, clean_b, clean_j, nunk): Sums = c.query_row(
            &format!("WITH a AS (SELECT r.remote_key, r.kind, r.at_risk, s.bytes, coalesce(j.junk, 0) junk FROM repos r JOIN dir_stats s ON s.dir = r.dir {JUNK}
                                 WHERE {wh} AND r.remote_key IS NOT NULL),
                           m AS (SELECT * FROM a WHERE kind <> 'vendored' OR {}),
                           v AS (SELECT count(*) n, coalesce(sum(bytes), 0) b FROM a WHERE kind = 'vendored'),
                           g AS (SELECT count(*) n, sum(bytes) - max(bytes) extra FROM m WHERE kind = 'repo' GROUP BY remote_key HAVING count(*) > 1),
                           w AS (SELECT count(*) n, coalesce(sum(bytes), 0) b, coalesce(sum(junk), 0) j FROM m WHERE kind = 'worktree'),
                           k AS (SELECT count(*) n, coalesce(sum(bytes), 0) b, coalesce(sum(junk), 0) j FROM m
                                 WHERE at_risk = 0 AND remote_key IN (SELECT remote_key FROM m GROUP BY 1 HAVING count(*) > 1)),
                           x AS (SELECT count(*) n FROM m WHERE at_risk IS NULL AND remote_key IN (SELECT remote_key FROM m GROUP BY 1 HAVING count(*) > 1))
                      SELECT (SELECT count(*) FROM g), (SELECT coalesce(sum(n), 0) FROM g), (SELECT coalesce(sum(extra), 0) FROM g), w.n, w.b, w.j, v.n, v.b,
                             k.n, k.b, k.j, x.n FROM w, v, k, x",
                     a.vendored as i32),
            params_from_iter(&args[..args.len() - 1]),
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?)),
        )?;
        let b = crate::fmt::bytes;
        let vnote = match (nv, a.vendored) {
            (0, _) => String::new(),
            (_, true) => format!("{nv} vendored clones ({}) included. ", b(v_bytes)),
            (_, false) => format!("{nv} vendored clones ({}, inside another repo's hidden tool dir like .external_modules) left out; --vendored to include. ", b(v_bytes)),
        };
        let unk = if nunk > 0 { format!(" {nunk} could not be checked (\"unknown\"): look yourself.") } else { String::new() };
        t.note = Some(format!(
            "{groups} remotes are cloned more than once ({copies} full clones, {} beyond the largest clone of each); \
             {nwt} worktrees use {} ({} of it build/deps). Same head = same commit. {vnote}\n\
             Before deleting: {nclean} copies show no sign of local work ({}, {} of it build/deps).{unk} \
             \"local work\" reads .git only: edited tracked files, unpushed branches, stashes, worktrees; untracked files are NOT checked. \
             Free build/deps first (target, node_modules, .venv: rebuildable). Drop a worktree with `git worktree remove <path>`, not the Trash; \
             never delete a repo that says \"main repo of N worktrees\".",
            b(extra), b(wt_bytes), b(wt_junk), b(clean_b), b(clean_j)
        ));
        return Ok(t);
    }
    let sql = format!(
        "SELECT r.path, r.kind, coalesce(r.remote, ''), r.branch, substr(r.head, 1, 10), r.activity, s.bytes, coalesce(j.junk, 0), coalesce(r.risk, '')
         FROM repos r JOIN dir_stats s ON s.dir = r.dir {JUNK} WHERE {wh} ORDER BY {order} LIMIT ?{lim}");
    let mut t = crate::query::table(&c, &sql, &args, &[("path", p), ("kind", p), ("remote", p), ("branch", p), ("head", p),
        ("last activity", Render::Date), ("size", Render::Bytes), ("build/deps", Render::Bytes), ("local work", p)])?;
    let (n, nr, nw, nrisk): (i64, i64, i64, i64) = c.query_row(
        &format!("SELECT count(*), coalesce(sum(r.remote IS NULL), 0), coalesce(sum(r.kind <> 'repo'), 0), coalesce(sum(r.at_risk), 0) FROM repos r WHERE {wh}"),
        params_from_iter(&args[..args.len() - 1]),
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    t.note = Some(format!("{n} repos ({nw} vendored/worktrees/submodules, {nr} without a remote, {nrisk} with local work that deleting would lose; \
        untracked files not checked); --dups for duplicate checkouts, --no-remote for local-only work, -s junk for rebuildable build/deps"));
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::{normalize, strip_auth, vendored};
    #[test]
    fn urls() {
        assert!(vendored("/g/infra", "/g/infra/.external_modules/github.com/x/y/abc"));
        assert!(!vendored("/g/work", "/g/work/project"));
        assert!(!vendored("/h/.dotfiles", "/h/.dotfiles/x"));
        let k = |u| normalize(u).unwrap();
        assert_eq!(k("git@github.com:Org/Repo.git"), "github.com/org/repo");
        assert_eq!(k("https://github.com/org/repo"), "github.com/org/repo");
        assert_eq!(k("https://user:tok@github.com/org/repo.git/"), "github.com/org/repo");
        assert_eq!(k("ssh://git@github.com:22/org/repo.git"), "github.com/org/repo");
        assert_eq!(k("git@ssh.dev.azure.com:v3/o/p/r"), k("https://o@dev.azure.com/o/p/_git/r"));
        assert_eq!(strip_auth("https://user:tok@github.com/a/b"), "https://github.com/a/b");
        assert_eq!(strip_auth("ssh://git@host/a/b"), "ssh://git@host/a/b");
        assert_eq!(strip_auth("git@github.com:a/b.git"), "git@github.com:a/b.git");
        assert_eq!(strip_auth("https://u:ab/cd@git-codecommit.example.com/v1/repos/x"), "https://git-codecommit.example.com/v1/repos/x");
        assert_eq!(strip_auth("https://host/a/b@v2"), "https://host/a/b@v2");
        assert_eq!(k("https://u:ab/cd@git-codecommit.example.com/v1/repos/x"), "git-codecommit.example.com/v1/repos/x");
    }
}
