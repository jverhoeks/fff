use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::PathBuf;

pub const SCHEMA_VERSION: i64 = 6;

/// Tables created before the bulk load. Indexes are created afterwards (faster).
pub const SCHEMA: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- namespace as a tree. ids are assigned parent-before-child, so id order is
-- a topological order (used for roll-ups).
CREATE TABLE dirs (
    id        INTEGER PRIMARY KEY,
    parent    INTEGER,            -- NULL for scan roots
    name      TEXT NOT NULL,      -- full path for roots
    path      TEXT NOT NULL,      -- absolute path (denormalised: makes ad-hoc SQL easy)
    opaque    INTEGER NOT NULL DEFAULT 0,  -- sized, but children not indexed (node_modules, .git, caches)
    is_repo   INTEGER NOT NULL DEFAULT 0,  -- contains .git
    repo_root INTEGER                      -- nearest enclosing repo dir (self if is_repo)
);

CREATE TABLE files (
    id     INTEGER PRIMARY KEY,
    dir    INTEGER NOT NULL,
    name   TEXT NOT NULL,
    ext    TEXT NOT NULL,
    kind   TEXT NOT NULL,
    kind_source INTEGER NOT NULL DEFAULT 0,   -- 0 ext, 1 magic
    mime   TEXT,
    size   INTEGER NOT NULL,     -- logical bytes
    alloc  INTEGER NOT NULL,     -- st_blocks * 512
    mtime  INTEGER NOT NULL,     -- ns since epoch
    dev    INTEGER NOT NULL,
    ino    INTEGER NOT NULL,
    nlink  INTEGER NOT NULL,
    flags  INTEGER NOT NULL      -- st_flags (SF_DATALESS = 0x40000000: iCloud, not downloaded)
);

-- subtree totals per directory (includes opaque contents)
CREATE TABLE dir_stats (
    dir        INTEGER PRIMARY KEY,
    files      INTEGER NOT NULL,
    dirs       INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    alloc      INTEGER NOT NULL,
    own_bytes  INTEGER NOT NULL,   -- files directly in this dir
    max_child  INTEGER NOT NULL,   -- bytes of the largest child dir
    depth      INTEGER NOT NULL
);

-- package manifests found inside opaque dirs (node_modules/*/package.json, *.dist-info,
-- .m2 and Gradle-cache *.pom, cargo registry Cargo.toml). Input for the CVE inventory; lockfiles
-- outside opaque dirs are ordinary rows in `files`.
CREATE TABLE manifests (
    dir       INTEGER NOT NULL,   -- the opaque dir (dirs.id) it was found under
    path      TEXT NOT NULL,
    ecosystem TEXT NOT NULL       -- npm | pypi | maven (*.pom, Gradle-cache version dir) | cargo
);

-- package inventory (installed packages, lockfile pins, declared ranges), filled at the end of scan;
-- the input for CVE matching. One row per (package version, file it was read from).
CREATE TABLE packages (
    ecosystem TEXT NOT NULL,      -- npm | pypi | maven | cargo | go | brew (Homebrew formula/cask)
    name      TEXT NOT NULL,      -- npm: @scope/name; pypi: PEP 503 normalised; maven: group:artifact
    version   TEXT NOT NULL,      -- resolved version; for source = 'declared' the range ('>=2.0,<3', '^2.1', '*')
    purl      TEXT,               -- pkg:npm/%40babel/core@7.24.0; NULL for declared ranges
    source    TEXT NOT NULL,      -- installed | lockfile (package-lock, pnpm, yarn, Cargo.lock, poetry, uv, go.mod, gradle.lockfile)
                                  -- | declared (requirements/pyproject/package.json/Cargo.toml/pom.xml/libs.versions.toml range;
                                  --   maven '*' = version set by a parent pom or BOM, so any version could land there)
    path      TEXT NOT NULL,      -- manifest / dist-info dir / lockfile it came from
    dir       INTEGER             -- dirs.id: the opaque dir (node_modules, .venv…) or the lockfile's dir;
                                  -- NULL for system installs outside the scan roots (Homebrew, global npm/pip)
);

-- git repositories (dirs with a .git dir or file), read from .git at scan time; no git binary, no network
CREATE TABLE repos (
    dir        INTEGER PRIMARY KEY, -- dirs.id of the working tree (join dir_stats for size)
    path       TEXT NOT NULL,
    kind       TEXT NOT NULL,       -- repo | vendored (inside another repo under a hidden dir: .external_modules, .terraform) | worktree | submodule
    remote     TEXT,                -- origin URL (else first remote), credentials stripped; NULL = local only
    remote_key TEXT,                -- normalised host/owner/name, lowercase: same key = same project
    branch     TEXT,                -- NULL when detached
    head       TEXT,                -- commit sha of HEAD
    main       TEXT,                -- worktree/submodule: path of the repo that owns its objects
    activity   INTEGER NOT NULL,    -- ns: newest mtime of .git/index, logs/HEAD, HEAD (last checkout/commit)
    -- what deleting this checkout would lose (src/gitstate.rs; read from .git, untracked files NOT checked)
    worktrees  INTEGER,             -- live linked worktrees that use this repo's history (deleting it breaks them)
    unpushed   INTEGER,             -- local branches whose tip was never on a remote (heuristic: remote refs + reflogs)
    stash      INTEGER,             -- stash entries
    changed    INTEGER,             -- tracked files edited/deleted vs .git/index; NULL = not checked
    at_risk    INTEGER,             -- 1 = local work found, 0 = no sign of it, NULL = could not check (see risk)
    risk       TEXT                 -- one-line verdict: "main repo of 4 worktrees; 2 unpushed branches (…)" | "no sign of local work" | "unknown (…)"
);
"#;

pub const INDEXES: &str = r#"
CREATE INDEX files_dir  ON files(dir);
CREATE INDEX files_size ON files(size);
CREATE INDEX files_kind ON files(kind, size);
CREATE INDEX files_ext  ON files(ext);
CREATE INDEX files_ino  ON files(dev, ino);
CREATE INDEX dirs_parent ON dirs(parent);
CREATE INDEX dir_stats_bytes ON dir_stats(bytes);
CREATE INDEX dirs_path ON dirs(path);
CREATE INDEX manifests_dir ON manifests(dir);
CREATE INDEX packages_name ON packages(name, version);
CREATE INDEX repos_key ON repos(remote_key);
CREATE INDEX dirs_repo ON dirs(repo_root);
CREATE INDEX packages_dir ON packages(dir);

-- convenience views for `fff sql`
CREATE VIEW v_files AS
  SELECT f.*, d.path || '/' || f.name AS path, d.repo_root
  FROM files f JOIN dirs d ON d.id = f.dir;
CREATE VIEW v_dirs AS
  SELECT d.id, d.parent, d.path, d.name, d.opaque, d.is_repo, d.repo_root, s.*
  FROM dirs d JOIN dir_stats s ON s.dir = d.id;
"#;

/// Survives rescans (lives in its own file): content hashes keyed by file identity.
pub const CACHE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS hashes (
    dev    INTEGER NOT NULL,
    ino    INTEGER NOT NULL,
    size   INTEGER NOT NULL,
    mtime  INTEGER NOT NULL,
    prefix BLOB,             -- blake3 of first+last 4 KiB
    full   BLOB,             -- blake3 of whole file
    PRIMARY KEY (dev, ino)
) WITHOUT ROWID;
"#;

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FFF_HOME") {
        return PathBuf::from(d);
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let dir = home.join(".local/share/fff");
    // fff used to be called findfiles: carry its index and hash cache over once
    let old = home.join(".local/share/findfiles");
    if !dir.exists() && old.is_dir() {
        let _ = std::fs::rename(&old, &dir);
    }
    dir
}

pub fn index_path() -> PathBuf {
    data_dir().join("index.db")
}

pub fn open_index() -> Result<Connection> {
    let p = index_path();
    if !p.exists() {
        anyhow::bail!("no index at {} — run `fff scan` first", p.display());
    }
    let c = Connection::open(&p).with_context(|| format!("open {}", p.display()))?;
    c.execute_batch("PRAGMA query_only=0; PRAGMA cache_size=-200000; PRAGMA mmap_size=1073741824;")?;
    attach_cache(&c)?;
    Ok(c)
}

pub fn attach_cache(c: &Connection) -> Result<()> {
    let p = data_dir().join("hashes.db");
    c.execute("ATTACH DATABASE ?1 AS cache", [p.to_string_lossy()])?;
    c.execute_batch(&CACHE_SCHEMA.replace("hashes (", "cache.hashes ("))?;
    Ok(())
}

/// Human/LLM-oriented description of the schema (MCP `schema` tool, `fff schema`).
pub fn schema_doc() -> String {
    format!("{SCHEMA}\n{INDEXES}\n{CACHE_SCHEMA}\n{NOTES}")
}

const NOTES: &str = r#"
-- NOTES
-- * dir_stats are SUBTREE totals (bytes includes everything below). own_bytes = files directly in the dir.
-- * opaque dirs (node_modules, .git, .venv, target, .cache, ...) are sized but their files are NOT in `files`.
-- * packages with dir IS NULL come from the system pass (Homebrew Cellar/Caskroom, packages vendored in kegs,
--   global npm/pip, ~/Library/Python); their paths are not in dirs/files. Never JOIN packages to dirs with an inner join.
-- * packages: "where is pandas 2.1.0" = source IN ('installed','lockfile') AND version = '2.1.0'; declared rows hold
--   ranges, so compare them with `fff packages pandas -x -v 2.1.0` (it evaluates the range), not with SQL '='.
--   Go versions keep their leading v (v1.2.3); maven names are group:artifact.
-- * repos: duplicate checkouts = same remote_key: SELECT remote_key, count(*) FROM repos WHERE kind <> 'vendored' GROUP BY 1 HAVING count(*) > 1
--   (or `fff repos --dups`); size via JOIN dir_stats ON dir_stats.dir = repos.dir
-- * repos safe-to-delete: at_risk = 0 means no sign of local work in .git (untracked files NOT checked); at_risk IS NULL = unknown,
--   treat as risky. worktrees > 0 = deleting it breaks linked worktrees. Rebuildable bytes: opaque dirs other than .git under the repo.
-- * path-prefix filter (index-friendly, case-sensitive): path = '/x' OR (path >= '/x/' AND path < '/x0')
-- * mtime is nanoseconds since epoch: date(mtime/1e9,'unixepoch')
-- * flags & 0x40000000 = iCloud file not downloaded (dataless)
-- * size = logical bytes, alloc = bytes on disk; hardlinks counted per name
-- * dup_files exists after running `dups`: grp, file_id, hash, size, clone_id, private_size
--   (same clone_id = APFS clones sharing blocks; private_size = bytes freed by deleting it)
-- * cache.hashes: content hashes (blake3) keyed by dev+ino
"#;
