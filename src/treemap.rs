//! `fff treemap`: WinDirStat-style treemap as one self-contained HTML file.
//! Nodes = dirs and files above a size threshold (a fraction of the root), taken
//! straight from dir_stats; everything smaller is shown as a per-dir remainder.

use crate::db;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const PAGE: &str = include_str!("treemap.html");

pub struct Args {
    pub under: Option<String>,
    /// smallest node as a fraction of the root (default 0.0001 = 0.01%)
    pub min_frac: f64,
    pub out: Option<PathBuf>,
    pub open: bool,
}

/// Tree data for the page: {total, threshold, nodes: [[parent, name, bytes, type]…]}
pub fn build(a: &Args) -> Result<(Value, usize)> {
    let c = db::open_index()?;
    // root: one dir, or a virtual root over all scan roots
    let roots: Vec<(i64, String, i64)> = match &a.under {
        Some(u) => {
            let u = std::fs::canonicalize(u).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| u.clone());
            vec![c.query_row(
                "SELECT d.id, d.path, s.bytes FROM dirs d JOIN dir_stats s ON s.dir = d.id WHERE d.path = ?1",
                [&u],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).map_err(|_| anyhow::anyhow!("{u} is not an indexed directory"))?]
        }
        None => c
            .prepare("SELECT d.id, d.path, s.bytes FROM dirs d JOIN dir_stats s ON s.dir = d.id WHERE d.parent IS NULL")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?,
    };
    let total: i64 = roots.iter().map(|r| r.2).sum();
    let thresh = ((total as f64 * a.min_frac) as i64).max(1);

    // nodes: [parent index, name, bytes, type]; index 0 = root
    let title = if roots.len() == 1 { roots[0].1.clone() } else { "all roots".to_string() };
    let mut nodes: Vec<Value> = vec![json!([-1, title, total, "d"])];
    let mut idx: HashMap<i64, usize> = HashMap::new();
    let multi = roots.len() > 1;
    for (id, path, bytes) in &roots {
        if multi {
            idx.insert(*id, nodes.len());
            nodes.push(json!([0, path, bytes, "d"]));
        } else {
            idx.insert(*id, 0);
        }
    }
    let mut seen_paths = 0usize;
    // One pass over dirs and one over files. With several roots (home + iCloud Drive, which
    // lives inside home's path range) query everything; with one root use its path range.
    let (filter, lo, hi, rid) = if multi {
        ("1 = 1", String::new(), String::new(), -1)
    } else {
        let r = &roots[0];
        ("(d.id = ?4 OR (d.path >= ?2 AND d.path < ?3))", format!("{}/", r.1), format!("{}0", r.1), r.0)
    };
    // ids are parent-before-child, so ORDER BY id guarantees parents are placed first
    let mut st = c.prepare(&format!(
        "SELECT d.id, d.parent, d.name, s.bytes, d.opaque, d.is_repo FROM dirs d JOIN dir_stats s ON s.dir = d.id
         WHERE s.bytes >= ?1 AND {filter} AND ?2 = ?2 AND ?3 = ?3 AND ?4 = ?4 ORDER BY d.id"
    ))?;
    let mut rows = st.query(rusqlite::params![thresh, lo, hi, rid])?;
    while let Some(r) = rows.next()? {
        let (id, parent, name, bytes, opaque, repo): (i64, Option<i64>, String, i64, bool, bool) =
            (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
        if idx.contains_key(&id) {
            continue; // a root
        }
        if let Some(&p) = parent.and_then(|p| idx.get(&p)) {
            idx.insert(id, nodes.len());
            nodes.push(json!([p, name, bytes, if opaque { "o" } else if repo { "g" } else { "d" }]));
        }
    }
    let mut st = c.prepare(&format!(
        "SELECT f.dir, f.name, f.size, f.kind FROM files f JOIN dirs d ON d.id = f.dir
         WHERE f.size >= ?1 AND {filter} AND ?2 = ?2 AND ?3 = ?3 AND ?4 = ?4"
    ))?;
    let mut rows = st.query(rusqlite::params![thresh, lo, hi, rid])?;
    while let Some(r) = rows.next()? {
        let (dir, name, size, kind): (i64, String, i64, String) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
        if let Some(&p) = idx.get(&dir) {
            nodes.push(json!([p, name, size, kind]));
            seen_paths += 1;
        }
    }
    Ok((json!({"total": total, "threshold": thresh, "nodes": nodes}), seen_paths))
}

fn page(data: &Value, api: Option<&str>) -> Result<String> {
    let mut html = PAGE.replace("/*DATA*/null", &serde_json::to_string(data)?.replace('<', "\\u003c"));
    if let Some(tok) = api {
        html = html.replace("/*API*/null", &format!("{:?}", tok));
    }
    Ok(html)
}

pub fn run(a: &Args) -> Result<String> {
    let (data, seen_paths) = build(a)?;
    let nodes = data["nodes"].as_array().map(|v| v.len()).unwrap_or(0);
    let thresh = data["threshold"].as_i64().unwrap_or(0);
    let html = page(&data, None)?;
    let out = a.out.clone().unwrap_or_else(|| db::data_dir().join("treemap.html"));
    std::fs::write(&out, html)?;
    if a.open {
        let _ = std::process::Command::new("open").arg(&out).status();
    }
    Ok(format!(
        "{} ({} nodes, {} files ≥ {}) — {}",
        out.display(),
        nodes,
        seen_paths,
        crate::fmt::bytes(thresh),
        if a.open { "opened in browser" } else { "open it in a browser" }
    ))
}

// ---------------------------------------------------------------------------
// `treemap --serve`: the same page plus actions (reveal, open, trash) through a
// localhost-only server. Every request must carry the per-run token in an
// X-Token header: a custom header means a cross-site page cannot send it
// without a CORS preflight, which this server never answers.

fn token() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn serve(a: &Args, port: u16) -> Result<()> {
    let tok = token();
    build(a)?; // fail early (no index, bad --under)
    let l = std::net::TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}/");
    // DNS-rebinding guard: only these Host headers are served
    let hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    eprintln!("treemap with actions at {url}  (Ctrl-C to stop)");
    if a.open {
        let _ = std::process::Command::new("open").arg(&url).status();
    }
    std::thread::scope(|sc| {
        for stream in l.incoming() {
            let Ok(st) = stream else { continue };
            let (tok, hosts) = (&tok, &hosts);
            sc.spawn(move || handle(st, a, tok, hosts));
        }
    });
    Ok(())
}

fn handle(mut st: std::net::TcpStream, a: &Args, tok: &str, hosts: &[String]) {
    use std::io::{BufRead, BufReader, Read, Write};
    let _ = st.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let Ok(clone) = st.try_clone() else { return };
    let mut rd = BufReader::new(clone);
    let mut line = String::new();
    if rd.read_line(&mut line).is_err() {
        return;
    }
    let (mut len, mut ok_tok, mut ok_host) = (0usize, false, false);
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                len = v.parse().unwrap_or(0).min(1 << 20);
            } else if k.eq_ignore_ascii_case("x-token") {
                ok_tok = v == tok;
            } else if k.eq_ignore_ascii_case("host") {
                ok_host = hosts.iter().any(|x| x == v);
            }
        }
    }
    let mut body = vec![0u8; len];
    let _ = rd.read_exact(&mut body);
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (status, ctype, out) = match (method, path) {
        _ if !ok_host => ("421 Misdirected Request", "text/plain", "bad host".to_string()),
        // rebuilt on every load, so a reload reflects trashed items
        ("GET", "/") => match build(a).and_then(|(d, _)| page(&d, Some(tok))) {
            Ok(h) => ("200 OK", "text/html; charset=utf-8", h),
            Err(e) => ("500 Internal Server Error", "text/plain", format!("{e:#}")),
        },
        ("POST", p) if p.starts_with("/api/") && ok_tok => {
            let r = serde_json::from_slice::<Value>(&body)
                .map_err(anyhow::Error::from)
                .and_then(|v| action(&p[5..], v["path"].as_str().unwrap_or(""), v["force"].as_bool().unwrap_or(false)));
            match r {
                // the Trash guard found local git work: the page asks again, naming it, and resends with force
                Ok(v) if v.get("warnings").is_some() => ("409 Conflict", "application/json", v.to_string()),
                Ok(v) => ("200 OK", "application/json", v.to_string()),
                Err(e) => ("400 Bad Request", "application/json", json!({"error": format!("{e:#}")}).to_string()),
            }
        }
        ("POST", _) => ("403 Forbidden", "text/plain", "bad token".into()),
        _ => ("404 Not Found", "text/plain", "not found".into()),
    };
    let _ = write!(st, "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{out}", out.len());
}

/// Only paths that are in the index can be acted on. Returns whether it is a scan root.
fn indexed(c: &rusqlite::Connection, path: &str) -> Result<bool> {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let (n, root): (i64, i64) = c.query_row(
        "SELECT (SELECT count(*) FROM dirs WHERE path = ?1)
              + (SELECT count(*) FROM files f JOIN dirs d ON d.id = f.dir WHERE d.path = ?2 AND f.name = ?3),
                (SELECT count(*) FROM dirs WHERE path = ?1 AND parent IS NULL)",
        rusqlite::params![path, dir, name],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    anyhow::ensure!(n > 0, "{path} is not in the index");
    anyhow::ensure!(std::path::Path::new(path).symlink_metadata().is_ok(), "{path} no longer exists");
    Ok(root > 0)
}

fn action(what: &str, path: &str, force: bool) -> Result<Value> {
    anyhow::ensure!(path.starts_with('/'), "absolute path required");
    let c = db::open_index()?;
    c.busy_timeout(std::time::Duration::from_secs(10))?;
    let is_root = indexed(&c, path)?;
    let run = |cmd: &mut std::process::Command| -> Result<()> {
        let o = cmd.output()?;
        anyhow::ensure!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr).trim());
        Ok(())
    };
    match what {
        "reveal" => run(std::process::Command::new("open").arg("-R").arg(path))?,
        "open" => run(std::process::Command::new("open").arg(path))?,
        "trash" => {
            anyhow::ensure!(!is_root, "{path} is a scan root; refusing to trash it");
            let warnings = git_guard(&c, path)?;
            if !warnings.is_empty() && !force {
                return Ok(json!({"warnings": warnings}));
            }
            let t0 = std::time::Instant::now();
            trash::move_to_trash(path)?;
            let (bytes, files) = remove_from_index(&c, path)?;
            log_action("trash", path, bytes, files, &warnings);
            return Ok(json!({"ok": true, "bytes": bytes, "files": files, "ms": t0.elapsed().as_millis() as u64}));
        }
        _ => anyhow::bail!("unknown action {what}"),
    }
    Ok(json!({"ok": true}))
}

/// Trash guard: what moving `path` to the Trash would lose in git. Checks every checkout at or under it
/// (and the repo whose .git it is), live from .git for the first LIVE_MAX, from the scan for the rest.
/// Worktrees inside `path` go with their main repo, so only the ones outside count. Paths inside a working
/// tree (target/, node_modules, src/) trigger nothing. Read-only: it never runs git.
fn git_guard(c: &rusqlite::Connection, path: &str) -> Result<Vec<String>> {
    use crate::gitstate::{live_stat, read_state};
    const LIVE_MAX: usize = 25;
    const SHOW: usize = 8;
    let inside = |p: &str| p == path || p.starts_with(&format!("{path}/"));
    let mut targets: Vec<(String, String, Option<i64>, Option<String>)> = c
        .prepare("SELECT path, kind, at_risk, risk FROM repos WHERE path = ?1 OR (path >= ?2 AND path < ?3) ORDER BY path")?
        .query_map(rusqlite::params![path, format!("{path}/"), format!("{path}0")], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let pp = std::path::Path::new(path);
    let mut history_of = None;
    if pp.file_name().is_some_and(|n| n == ".git") {
        if let Some(parent) = pp.parent() {
            history_of = Some(parent.to_string_lossy().into_owned());
            targets.insert(0, (parent.to_string_lossy().into_owned(), "repo".into(), None, None));
        }
    } else if pp.join(".git").exists() && !targets.iter().any(|t| t.0 == path) {
        targets.insert(0, (path.to_string(), "repo".into(), None, None));
    }
    let mut out = vec![];
    let mut hidden = 0;
    for (i, (p, kind, at_risk, risk)) in targets.iter().enumerate() {
        let root = std::path::Path::new(p);
        let live = if i < LIVE_MAX { Some(read_state(root, &live_stat(root))) } else { None };
        let mut line = if let Some(Some(mut st)) = live {
            st.worktrees.retain(|w| !inside(w));
            let mut r = st.risks();
            if kind == "worktree" || st.worktree {
                let main = st.main.clone().unwrap_or_default();
                if !inside(&main) {
                    r.push(format!("is a worktree of {main}: `git -C {main} worktree remove {p}` keeps git's records clean (the branch stays in {main})"));
                }
            }
            if r.is_empty() && !st.unknown.is_empty() {
                r.push(format!("could not check: {}", st.unknown.join(", ")));
            }
            r.join("; ")
        } else if let Some(None) = live {
            // .git unreadable now: never treat that as clean
            format!("could not read its .git now; last scan: {}", risk.clone().unwrap_or_else(|| "not checked".into()))
        } else if *at_risk == Some(1) {
            format!("{} (as of the last scan)", risk.clone().unwrap_or_default())
        } else {
            String::new()
        };
        if line.is_empty() {
            continue;
        }
        if history_of.as_deref() == Some(p.as_str()) {
            line = format!("this is the git history of {p}; {line}");
        }
        if out.len() < SHOW {
            out.push(format!("{p}: {line}"));
        } else {
            hidden += 1;
        }
    }
    if let (Some(h), true) = (history_of, out.is_empty()) {
        out.push(format!("this is the git history of {h}: the checkout stays, but it is no longer a git repo"));
    }
    if hidden > 0 {
        out.push(format!("+{hidden} more checkouts with local work (fff repos -u '{path}')"));
    }
    if targets.len() > LIVE_MAX {
        out.push(format!("{} checkouts below it; the first {LIVE_MAX} were checked now, the rest from the last scan", targets.len()));
    }
    Ok(out)
}

/// NSFileManager.trashItemAtURL via the Objective-C runtime (no crates, no AppleScript):
/// a rename into the volume's Trash, so it is instant even for huge folders.
mod trash {
    use std::ffi::{c_char, c_void, CStr, CString};
    type Id = *mut c_void;
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Id;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(p: *mut c_void);
    }
    fn sel(n: &str) -> Id {
        let c = CString::new(n).unwrap();
        unsafe { sel_registerName(c.as_ptr()) }
    }
    fn class(n: &str) -> Id {
        let c = CString::new(n).unwrap();
        unsafe { objc_getClass(c.as_ptr()) }
    }
    pub fn move_to_trash(path: &str) -> anyhow::Result<()> {
        let cpath = CString::new(path)?;
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let send0: extern "C" fn(Id, Id) -> Id = std::mem::transmute(objc_msgSend as *const ());
            let send1: extern "C" fn(Id, Id, *const c_void) -> Id = std::mem::transmute(objc_msgSend as *const ());
            let send3: extern "C" fn(Id, Id, Id, *mut Id, *mut Id) -> i8 = std::mem::transmute(objc_msgSend as *const ());
            let s = send1(class("NSString"), sel("stringWithUTF8String:"), cpath.as_ptr() as *const c_void);
            let url = send1(class("NSURL"), sel("fileURLWithPath:"), s as *const c_void);
            let fm = send0(class("NSFileManager"), sel("defaultManager"));
            let mut err: Id = std::ptr::null_mut();
            let ok = send3(fm, sel("trashItemAtURL:resultingItemURL:error:"), url, std::ptr::null_mut(), &mut err);
            let msg = if ok == 0 && !err.is_null() {
                let d = send0(err, sel("localizedDescription"));
                let p = send0(d, sel("UTF8String")) as *const c_char;
                Some(if p.is_null() { "unknown error".into() } else { CStr::from_ptr(p).to_string_lossy().into_owned() })
            } else if ok == 0 {
                Some("trash failed".to_string())
            } else {
                None
            };
            objc_autoreleasePoolPop(pool);
            match msg {
                Some(m) => anyhow::bail!("{m}"),
                None => Ok(()),
            }
        }
    }
}

fn log_action(what: &str, path: &str, bytes: i64, files: i64, confirmed: &[String]) {
    use std::io::Write;
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(db::data_dir().join("actions.log")) {
        let mut e = json!({"ts": ts, "action": what, "path": path, "bytes": bytes, "files": files});
        if !confirmed.is_empty() {
            e["confirmed_despite"] = json!(confirmed);
        }
        let _ = writeln!(f, "{e}");
    }
}

/// Drop a trashed file or subtree from the index and subtract it from every ancestor's totals.
fn remove_from_index(c: &rusqlite::Connection, path: &str) -> Result<(i64, i64)> {
    use rusqlite::params;
    // IMMEDIATE: two quick Trash clicks run on two threads; a deferred read-then-write would fail with BUSY_SNAPSHOT
    let tx = rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
    let dir: Option<(i64, Option<i64>, i64, i64, i64, i64)> = tx
        .query_row(
            "SELECT d.id, d.parent, s.bytes, s.alloc, s.files, s.dirs FROM dirs d JOIN dir_stats s ON s.dir = d.id WHERE d.path = ?1",
            [path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .ok();
    let (parent, bytes, alloc, files, dirs) = if let Some((id, parent, bytes, alloc, files, dirs)) = dir {
        let (lo, hi) = (format!("{path}/"), format!("{path}0"));
        let sub = "SELECT id FROM dirs WHERE id = ?1 OR (path >= ?2 AND path < ?3)";
        for t in ["DELETE FROM files WHERE dir IN (SUB)", "DELETE FROM packages WHERE dir IN (SUB)", "DELETE FROM manifests WHERE dir IN (SUB)", "DELETE FROM repos WHERE dir IN (SUB)", "DELETE FROM dir_stats WHERE dir IN (SUB)"] {
            tx.execute(&t.replace("SUB", sub), params![id, lo, hi])?;
        }
        tx.execute("DELETE FROM dirs WHERE id = ?1 OR (path >= ?2 AND path < ?3)", params![id, lo, hi])?;
        (parent, bytes, alloc, files, dirs + 1)
    } else {
        let (dpath, name) = path.rsplit_once('/').unwrap_or(("", path));
        let (fid, did, size, alloc): (i64, i64, i64, i64) = tx.query_row(
            "SELECT f.id, f.dir, f.size, f.alloc FROM files f JOIN dirs d ON d.id = f.dir WHERE d.path = ?1 AND f.name = ?2",
            params![dpath, name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        tx.execute("DELETE FROM files WHERE id = ?1", [fid])?;
        tx.execute("DELETE FROM packages WHERE path = ?1", [path])?;
        tx.execute("UPDATE dir_stats SET own_bytes = own_bytes - ?2 WHERE dir = ?1", params![did, size])?;
        (Some(did), size, alloc, 1, 0)
    };
    if let Some(p) = parent {
        tx.execute(
            "WITH RECURSIVE a(id) AS (SELECT ?1 UNION ALL SELECT d.parent FROM dirs d JOIN a ON d.id = a.id WHERE d.parent IS NOT NULL)
             UPDATE dir_stats SET bytes = bytes - ?2, alloc = alloc - ?3, files = files - ?4, dirs = dirs - ?5 WHERE dir IN (SELECT id FROM a)",
            params![p, bytes, alloc, files, dirs],
        )?;
    }
    tx.commit()?;
    Ok((bytes, files))
}
