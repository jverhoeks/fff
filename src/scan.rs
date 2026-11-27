//! Parallel walk → single writer → SQLite + names sidecar.
//!
//! Walkers (rayon) read directories and lstat entries; one writer thread owns
//! the database. Directory ids are assigned parent-before-child, so a pass in
//! increasing id order is top-down and decreasing id order is bottom-up.

use crate::{db, kinds, names};
use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::fs;
use std::os::macos::fs::MetadataExt as MacMeta;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct Options {
    pub roots: Vec<PathBuf>,
    pub excludes: Vec<PathBuf>,
    pub full: bool, // index inside node_modules, caches, … (only .git stays opaque)
    pub system: bool, // packages-only pass over Homebrew / global installs (packages::system)
    pub xdev: bool, // stay on the root's device
    pub threads: usize,
}

/// Directories that are sized but whose contents are not indexed file by file.
pub const OPAQUE: &[&str] = &[
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".terraform", ".terragrunt-cache", ".cache", ".npm",
    ".gradle", ".m2", ".cargo", ".rustup", ".pnpm-store", ".yarn", "DerivedData", ".next",
    ".nuxt", ".Trash", ".docker", ".orbstack", ".ollama", "cdktf.out",
];

struct FileRow {
    dir: i64,
    name: String,
    size: i64,
    alloc: i64,
    mtime: i64,
    dev: i64,
    ino: i64,
    nlink: i64,
    flags: i64,
    symlink: bool,
}

enum Msg {
    Dir { id: i64, parent: Option<i64>, name: String, opaque: bool, is_repo: bool },
    Files(Vec<FileRow>),
}

#[derive(Default)]
struct Acc {
    files: AtomicU64,
    dirs: AtomicU64,
    bytes: AtomicU64,
    alloc: AtomicU64,
}

struct Walker {
    tx: Sender<Msg>,
    next_dir: AtomicI64,
    opaque: HashSet<&'static str>,
    excludes: Vec<PathBuf>,
    xdev: bool,
    accs: Mutex<Vec<(i64, Arc<Acc>)>>,
    errors: AtomicU64,
    /// package manifests seen inside opaque dirs: (opaque dir id, path, ecosystem)
    manifests: Mutex<Vec<(i64, String, &'static str)>>,
}

impl Walker {
    fn is_opaque(&self, name: &str, siblings: &[(String, fs::Metadata)]) -> bool {
        self.opaque.contains(name)
            // Rust build output: target/ next to a Cargo.toml
            || (name == "target" && self.opaque.len() > 1 && siblings.iter().any(|(s, _)| s == "Cargo.toml"))
    }

    /// Read one directory; emit its own record and its files; recurse.
    fn walk<'s>(&'s self, s: &rayon::Scope<'s>, path: PathBuf, id: i64, parent: Option<i64>, name: String, dev: u64) {
        let mut entries: Vec<(String, fs::Metadata)> = Vec::new();
        match fs::read_dir(&path) {
            Ok(rd) => {
                for e in rd.flatten() {
                    // DirEntry::metadata does not follow symlinks (lstat)
                    match e.metadata() {
                        Ok(m) => entries.push((e.file_name().to_string_lossy().into_owned(), m)),
                        Err(_) => {
                            self.errors.fetch_add(1, Relaxed);
                        }
                    }
                }
            }
            Err(_) => {
                self.errors.fetch_add(1, Relaxed);
            }
        }
        let is_repo = entries.iter().any(|(n, _)| n == ".git");
        let _ = self.tx.send(Msg::Dir { id, parent, name, opaque: false, is_repo });

        let mut rows = Vec::new();
        for (cname, m) in &entries {
            if m.file_type().is_dir() {
                let cpath = path.join(cname);
                if (self.xdev && m.dev() != dev) || self.excludes.iter().any(|x| x == &cpath) {
                    continue;
                }
                let cid = self.next_dir.fetch_add(1, Relaxed);
                if self.is_opaque(cname, &entries) {
                    let acc = Arc::new(Acc::default());
                    self.accs.lock().unwrap().push((cid, acc.clone()));
                    let _ = self.tx.send(Msg::Dir { id: cid, parent: Some(id), name: cname.clone(), opaque: true, is_repo: false });
                    s.spawn(move |s| self.walk_opaque(s, cpath, acc, dev, cid));
                } else {
                    let (cname, cdev) = (cname.clone(), m.dev());
                    s.spawn(move |s| self.walk(s, cpath, cid, Some(id), cname, cdev));
                }
            } else {
                rows.push(FileRow {
                    dir: id,
                    name: cname.clone(),
                    size: m.len() as i64,
                    alloc: (m.blocks() * 512) as i64,
                    mtime: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
                    dev: m.dev() as i64,
                    ino: m.ino() as i64,
                    nlink: m.nlink() as i64,
                    flags: m.st_flags() as i64,
                    symlink: m.file_type().is_symlink(),
                });
            }
        }
        if !rows.is_empty() {
            let _ = self.tx.send(Msg::Files(rows));
        }
    }

    /// Size a subtree without emitting rows.
    fn walk_opaque<'s>(&'s self, s: &rayon::Scope<'s>, path: PathBuf, acc: Arc<Acc>, dev: u64, oid: i64) {
        // node_modules/<pkg>/ or node_modules/@scope/<pkg>/ — its package.json is a manifest
        let parent_name = |p: &Path, up: usize| p.ancestors().nth(up).and_then(|a| a.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let npm_pkg_dir = parent_name(&path, 1) == "node_modules"
            || (parent_name(&path, 2) == "node_modules" && parent_name(&path, 1).starts_with('@'));
        let Ok(rd) = fs::read_dir(&path) else {
            self.errors.fetch_add(1, Relaxed);
            return;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.file_type().is_dir() {
                if self.xdev && m.dev() != dev {
                    continue;
                }
                acc.dirs.fetch_add(1, Relaxed);
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".dist-info") || name.ends_with(".egg-info") {
                    self.manifests.lock().unwrap().push((oid, e.path().to_string_lossy().into_owned(), "pypi"));
                }
                // Gradle cache files-2.1/<group>/<artifact>/<version>: some versions hold only a jar or .module, no .pom
                if parent_name(&path, 2) == "files-2.1" {
                    self.manifests.lock().unwrap().push((oid, e.path().to_string_lossy().into_owned(), "maven"));
                }
                let acc = acc.clone();
                let p = e.path();
                s.spawn(move |s| self.walk_opaque(s, p, acc, dev, oid));
            } else {
                let name = e.file_name();
                let eco = match name.to_string_lossy() {
                    n if n == "package.json" && npm_pkg_dir => Some("npm"),
                    n if n.ends_with(".pom") && !path.components().any(|c| c.as_os_str() == "files-2.1") => Some("maven"),
                    n if n == "Cargo.toml" && path.components().any(|c| c.as_os_str() == "registry") => Some("cargo"),
                    _ => None,
                };
                if let Some(eco) = eco {
                    self.manifests.lock().unwrap().push((oid, e.path().to_string_lossy().into_owned(), eco));
                }
                acc.files.fetch_add(1, Relaxed);
                acc.bytes.fetch_add(m.len(), Relaxed);
                acc.alloc.fetch_add(m.blocks() * 512, Relaxed);
            }
        }
    }
}

#[derive(Default, Clone)]
struct DirRec {
    parent: Option<i64>,
    name: String,
    path: String,
    opaque: bool,
    is_repo: bool,
    present: bool,
    files: i64,
    dirs: i64,
    bytes: i64,
    alloc: i64,
    own_bytes: i64,
    max_child: i64,
    depth: i64,
    repo_root: Option<i64>,
}

struct WriterOut {
    dirs: Vec<DirRec>,
    names: names::Builder,
    files: u64,
}

fn ensure(dirs: &mut Vec<DirRec>, id: i64) -> &mut DirRec {
    let i = id as usize;
    if dirs.len() <= i {
        dirs.resize(i + 1, DirRec::default());
    }
    &mut dirs[i]
}

fn writer(conn: &Connection, rx: Receiver<Msg>) -> Result<WriterOut> {
    let mut ins = conn.prepare(
        "INSERT INTO files (id,dir,name,ext,kind,size,alloc,mtime,dev,ino,nlink,flags)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
    )?;
    let mut dirs: Vec<DirRec> = Vec::with_capacity(1 << 20);
    let mut nb = names::Builder::default();
    let mut fid: i64 = 0;
    for msg in rx {
        match msg {
            Msg::Dir { id, parent, name, opaque, is_repo } => {
                nb.push(&name, -id);
                let d = ensure(&mut dirs, id);
                d.parent = parent;
                d.name = name;
                d.opaque = opaque;
                d.is_repo = is_repo;
                d.present = true;
            }
            Msg::Files(rows) => {
                for r in rows {
                    fid += 1;
                    let ext = kinds::ext_of(&r.name);
                    let kind = if r.symlink { "symlink" } else { kinds::from_ext(&ext) };
                    ins.execute(params![
                        fid, r.dir, r.name, ext, kind, r.size, r.alloc, r.mtime, r.dev, r.ino,
                        r.nlink, r.flags
                    ])?;
                    nb.push(&r.name, fid);
                    let d = ensure(&mut dirs, r.dir);
                    d.files += 1;
                    d.own_bytes += r.size;
                    d.bytes += r.size;
                    d.alloc += r.alloc;
                }
            }
        }
    }
    Ok(WriterOut { dirs, names: nb, files: fid as u64 })
}

pub fn run(opts: Options) -> Result<String> {
    let t0 = Instant::now();
    let dir = db::data_dir();
    fs::create_dir_all(&dir)?;
    let tmp = dir.join("index.db.tmp");
    let _ = fs::remove_file(&tmp);

    let roots: Vec<PathBuf> = opts
        .roots
        .iter()
        .map(|r| fs::canonicalize(r).with_context(|| format!("root {}", r.display())))
        .collect::<Result<_>>()?;

    let (tx, rx) = bounded::<Msg>(8192);
    let tmp2 = tmp.clone();
    let writer_h = std::thread::spawn(move || -> Result<(Connection, WriterOut)> {
        let mut conn = Connection::open(&tmp2)?;
        conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-400000;")?;
        conn.execute_batch(db::SCHEMA)?;
        let t = conn.transaction()?;
        let out = writer(&t, rx)?;
        t.commit()?;
        Ok((conn, out))
    });

    let opaque: HashSet<&'static str> =
        if opts.full { [".git"].into_iter().collect() } else { OPAQUE.iter().copied().collect() };
    let walker = Walker {
        tx,
        next_dir: AtomicI64::new(1),
        opaque,
        excludes: opts.excludes.clone(),
        xdev: opts.xdev,
        accs: Mutex::new(Vec::new()),
        errors: AtomicU64::new(0),
        manifests: Mutex::new(Vec::new()),
    };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(opts.threads).build()?;
    pool.scope(|s| {
        for root in &roots {
            let id = walker.next_dir.fetch_add(1, Relaxed);
            let dev = fs::metadata(root).map(|m| m.dev()).unwrap_or(0);
            let w = &walker;
            let root = root.clone();
            let name = root.to_string_lossy().into_owned();
            s.spawn(move |s| w.walk(s, root, id, None, name, dev));
        }
    });
    let Walker { tx, accs, errors, manifests, .. } = walker;
    drop(tx); // closes the channel → writer drains and returns
    let (mut conn, WriterOut { mut dirs, names: nb, files }) =
        writer_h.join().map_err(|_| anyhow::anyhow!("writer panicked"))??;
    let t_walk = t0.elapsed();

    // opaque subtree totals
    let accs = accs.into_inner().unwrap();
    for (id, acc) in &accs {
        let d = &mut dirs[*id as usize];
        let b = acc.bytes.load(Relaxed) as i64;
        d.files += acc.files.load(Relaxed) as i64;
        d.dirs += acc.dirs.load(Relaxed) as i64;
        d.bytes += b;
        d.own_bytes += b;
        d.alloc += acc.alloc.load(Relaxed) as i64;
    }
    // top-down (increasing id): depth, path, repo_root
    for i in 1..dirs.len() {
        if !dirs[i].present {
            continue;
        }
        let (depth, inherited, path) = match dirs[i].parent {
            Some(p) => {
                let pd = &dirs[p as usize];
                let sep = if pd.path.ends_with('/') { "" } else { "/" };
                (pd.depth + 1, pd.repo_root, format!("{}{}{}", pd.path, sep, dirs[i].name))
            }
            None => (0, None, dirs[i].name.clone()),
        };
        let d = &mut dirs[i];
        d.depth = depth;
        d.path = path;
        d.repo_root = if d.is_repo { Some(i as i64) } else { inherited };
    }
    // bottom-up (decreasing id): subtree totals
    for i in (1..dirs.len()).rev() {
        if !dirs[i].present {
            continue;
        }
        if let Some(p) = dirs[i].parent {
            let (f, d, b, a) = (dirs[i].files, dirs[i].dirs, dirs[i].bytes, dirs[i].alloc);
            let pd = &mut dirs[p as usize];
            pd.files += f;
            pd.dirs += d + 1;
            pd.bytes += b;
            pd.alloc += a;
            pd.max_child = pd.max_child.max(b);
        }
    }

    let txn = conn.transaction()?;
    {
        let mut insd = txn.prepare(
            "INSERT INTO dirs (id,parent,name,path,opaque,is_repo,repo_root) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )?;
        let mut inss = txn.prepare(
            "INSERT INTO dir_stats (dir,files,dirs,bytes,alloc,own_bytes,max_child,depth)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        )?;
        for (i, d) in dirs.iter().enumerate() {
            if !d.present {
                continue;
            }
            let id = i as i64;
            insd.execute(params![id, d.parent, d.name, d.path, d.opaque, d.is_repo, d.repo_root])?;
            inss.execute(params![id, d.files, d.dirs, d.bytes, d.alloc, d.own_bytes, d.max_child, d.depth])?;
        }
        let mut insm = txn.prepare("INSERT INTO manifests (dir, path, ecosystem) VALUES (?1,?2,?3)")?;
        for (oid, p, eco) in manifests.lock().unwrap().iter() {
            insm.execute(params![oid, p, eco])?;
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let meta = [
            ("schema_version", db::SCHEMA_VERSION.to_string()),
            ("roots", roots.iter().map(|r| r.to_string_lossy()).collect::<Vec<_>>().join("\n")),
            ("scanned_at", now.to_string()),
            ("full", opts.full.to_string()),
        ];
        for (k, v) in meta {
            txn.execute("INSERT INTO meta VALUES (?1, ?2)", params![k, v])?;
        }
    }
    txn.execute_batch(db::INDEXES)?;
    txn.commit()?;
    let tp = std::time::Instant::now();
    let (npkgs, nsrc) = crate::packages::build(&conn, opts.threads)?;
    let mut pkg_note = format!("{npkgs} package versions from {nsrc} manifests/lockfiles in {:.1}s", tp.elapsed().as_secs_f64());
    if opts.system {
        let ts = std::time::Instant::now();
        let covered = |p: &Path| opts.roots.iter().any(|r| p.starts_with(r)) && !opts.excludes.iter().any(|x| p.starts_with(x));
        let n = crate::packages::system(&conn, opts.threads, &covered)?;
        pkg_note += &format!("; {n} system packages (Homebrew, global npm/pip) in {:.1}s", ts.elapsed().as_secs_f64());
    }
    let tr = std::time::Instant::now();
    let nrepos = crate::repos::build(&conn, opts.threads)?;
    let pkg_note = format!("{pkg_note}; {nrepos} git repos in {:.1}s", tr.elapsed().as_secs_f64());
    conn.execute_batch("ANALYZE; PRAGMA journal_mode=WAL;")?;
    drop(conn);

    nb.write(&dir)?;
    fs::rename(&tmp, db::index_path())?;

    let ndirs = dirs.iter().filter(|d| d.present).count();
    let total: i64 = dirs.iter().filter(|d| d.present && d.parent.is_none()).map(|d| d.bytes).sum();
    Ok(format!(
        "indexed {} files, {} dirs ({} opaque), {} in {:.1}s (walk+insert {:.1}s), {} unreadable; {}",
        files,
        ndirs,
        accs.len(),
        crate::fmt::bytes(total),
        t0.elapsed().as_secs_f64(),
        t_walk.as_secs_f64(),
        errors.load(Relaxed),
        pkg_note,
    ))
}

impl Options {
    /// Defaults: root = $HOME (+ iCloud Drive), ~/Library skipped (privacy prompts, app caches).
    #[allow(clippy::too_many_arguments)] // one per CLI flag
    pub fn from_cli(roots: Vec<PathBuf>, exclude: Vec<PathBuf>, library: bool, no_icloud: bool, no_system: bool, full: bool, cross_devices: bool, threads: usize) -> Result<Options> {
        let home = PathBuf::from(std::env::var("HOME")?);
        let default_roots = roots.is_empty();
        let mut roots = if default_roots { vec![home.clone()] } else { roots };
        let mut excludes: Vec<PathBuf> = exclude.iter().map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone())).collect();
        if !library {
            excludes.push(home.join("Library"));
            // iCloud Drive + app iCloud folders live under ~/Library/Mobile Documents.
            // Placeholders (not downloaded) are indexed by metadata only, never read.
            let icloud = home.join("Library/Mobile Documents");
            if default_roots && !no_icloud && icloud.is_dir() {
                roots.push(icloud);
            }
        }
        Ok(Options { roots, excludes, full, system: default_roots && !no_system, xdev: !cross_devices, threads })
    }
}
