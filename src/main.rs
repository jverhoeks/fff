mod db;
mod dups;
mod fmt;
mod gitstate;
mod kinds;
mod mcp;
mod names;
mod packages;
mod query;
mod repos;
mod scan;
mod sniff;
mod versions;
mod treemap;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const SKILL: &str = include_str!("../skills/fff/SKILL.md");

/// Index every file on this Mac; find by name, type, size; large dirs; duplicates; SQL.
#[derive(Parser)]
#[command(name = "fff", version)]
struct Cli {
    /// JSON output (raw numbers; for scripts and agents)
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// (Re)build the index. Default: $HOME plus iCloud Drive, skipping the rest of ~/Library.
    Scan {
        roots: Vec<PathBuf>,
        /// Extra directories to skip (absolute)
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Index all of ~/Library (may trigger privacy prompts)
        #[arg(long)]
        library: bool,
        /// Leave out iCloud Drive (~/Library/Mobile Documents)
        #[arg(long)]
        no_icloud: bool,
        /// Skip the packages-only pass over Homebrew and global npm/pip installs (only runs without explicit roots)
        #[arg(long)]
        no_system: bool,
        /// Index inside node_modules, caches, .venv … (only .git stays opaque)
        #[arg(long)]
        full: bool,
        /// Cross filesystem boundaries
        #[arg(long)]
        cross_devices: bool,
        #[arg(long, default_value_t = default_threads(2))]
        threads: usize,
    },
    /// Find files/dirs whose name contains all TERMS (case-insensitive)
    Find {
        terms: Vec<String>,
        /// document, slides, sheet, image, video, audio, archive, diskimage, code, data, font, binary, ebook, mail
        #[arg(short, long)]
        kind: Option<String>,
        #[arg(short, long)]
        ext: Option<String>,
        /// e.g. 100M
        #[arg(long)]
        min_size: Option<String>,
        /// Only below this directory
        #[arg(short, long)]
        under: Option<String>,
        /// Only directories
        #[arg(long)]
        dirs: bool,
        /// Only files
        #[arg(long)]
        files: bool,
        /// mtime | size | name
        #[arg(long, default_value = "mtime")]
        sort: String,
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: i64,
    },
    /// Large directories (from precomputed subtree totals) or files
    Big {
        /// du-like: children of this directory
        #[arg(short, long)]
        under: Option<String>,
        /// With --under: levels below it (default 1). Without: max depth from the scan root.
        #[arg(short, long)]
        depth: Option<i64>,
        /// Largest files instead of directories
        #[arg(long)]
        files: bool,
        /// All directories with this name, e.g. node_modules
        #[arg(long)]
        name: Option<String>,
        /// With --files: only this kind
        #[arg(short, long)]
        kind: Option<String>,
        #[arg(long, default_value = "100M")]
        min_size: String,
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: i64,
    },
    /// WinDirStat-style treemap as a self-contained HTML page
    Treemap {
        /// Root directory (default: all scan roots)
        #[arg(short, long)]
        under: Option<String>,
        /// Smallest box as a fraction of the root (smaller items are grouped)
        #[arg(long, default_value_t = 0.0001)]
        min_frac: f64,
        /// Output file (default: <data dir>/treemap.html)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Don't open it in the browser
        #[arg(long)]
        no_open: bool,
        /// Serve it on localhost with actions: Reveal in Finder, Open, Move to Trash
        #[arg(long)]
        serve: bool,
        /// Port for --serve (0 = any free port)
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Git repositories: remote, branch, last activity, size; --dups for duplicate checkouts
    Repos {
        /// Substring of the path or remote
        name: Option<String>,
        /// Group checkouts of the same remote (clones, copies, worktrees)
        #[arg(short, long)]
        dups: bool,
        /// Only repos without a remote (work that exists nowhere else)
        #[arg(long)]
        no_remote: bool,
        /// With --dups: include vendored clones (inside another repo's hidden dir, e.g. .external_modules)
        #[arg(long)]
        vendored: bool,
        /// Only below this directory
        #[arg(short, long)]
        under: Option<String>,
        /// activity | size | junk (build/deps bytes) | path
        #[arg(short, long, default_value = "activity")]
        sort: String,
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: i64,
    },
    /// Incident check: where are these (compromised) packages installed, pinned, or installable?
    /// Takes a pasted advisory list: `name@1.2.3`, `name 1.2.3, 1.2.4`, `name==1.2.3`, purls, bare names
    Check {
        /// Files with the list, or entries themselves (`@ctrl/tinycolor@4.1.1`); none = read stdin
        items: Vec<String>,
        /// npm | pypi | maven | cargo | go | brew (default: any)
        #[arg(short, long)]
        ecosystem: Option<String>,
        /// Only below this directory
        #[arg(short, long)]
        under: Option<String>,
        #[arg(short = 'n', long, default_value_t = 500)]
        limit: i64,
    },
    /// Installed packages, lockfile pins and declared ranges (npm, pypi, maven, cargo, go, brew) by name
    Packages {
        /// Substring of the package name (omit for a summary per ecosystem)
        name: Option<String>,
        /// Version or range: 2.1.0, '2.*', '^2.1', '~2.1', '>=2.1 <2.3', '1.x || 3.x', '~=2.1'.
        /// Also lists project files (requirements, pyproject, package.json, Cargo.toml) whose
        /// declared range overlaps it. '/regex/' matches resolved versions by regex instead
        #[arg(short, long)]
        version: Option<String>,
        /// Name must match exactly (pypi: PEP 503-normalised), so pandas ≠ geopandas
        #[arg(short = 'x', long)]
        exact: bool,
        /// npm | pypi | maven | cargo | go | brew
        #[arg(short, long)]
        ecosystem: Option<String>,
        /// installed | lockfile | declared
        #[arg(short, long)]
        source: Option<String>,
        /// Only below this directory
        #[arg(short, long)]
        under: Option<String>,
        /// One row per location instead of per version
        #[arg(long)]
        paths: bool,
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: i64,
    },
    /// Counts and bytes per kind (or per extension)
    Types {
        /// Break one kind down by extension
        #[arg(short, long)]
        kind: Option<String>,
        /// Group by extension
        #[arg(long)]
        ext: bool,
        #[arg(short = 'n', long, default_value_t = 40)]
        limit: i64,
    },
    /// Identify extension-less files by magic bytes
    Sniff {
        /// Also files with an unknown extension
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = default_threads(2))]
        threads: usize,
    },
    /// Find duplicate files (size → inode → edge hash → BLAKE3 → APFS clone check)
    Dups {
        #[arg(long, default_value = "1M")]
        min_size: String,
        /// Include */.cache/*, */Caches/*
        #[arg(long)]
        include_caches: bool,
        /// Groups to print
        #[arg(short = 'n', long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value_t = default_threads(1))]
        threads: usize,
    },
    /// Run SQL against the index (read-only unless --write). See `fff schema`.
    Sql {
        query: String,
        #[arg(long)]
        write: bool,
    },
    /// Print the index schema with notes for writing SQL
    Schema,
    /// Index summary
    Stats,
    /// Run as an MCP server on stdio (for Claude Code, Claude Desktop, other agents)
    Mcp,
    /// Print the agent skill (SKILL.md), or install it into ~/.claude/skills/fff
    Skill {
        #[arg(long)]
        install: bool,
    },
}

pub fn default_threads(mult: usize) -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8) * mult
}

fn main() -> Result<()> {
    // `fff … | head` should end quietly, not panic on a closed pipe
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let cli = Cli::parse();
    let json = cli.json;
    match cli.cmd {
        Cmd::Scan { roots, exclude, library, no_icloud, no_system, full, cross_devices, threads } => {
            let opts = scan::Options::from_cli(roots, exclude, library, no_icloud, no_system, full, cross_devices, threads)?;
            eprintln!("{}", scan::run(opts)?);
        }
        Cmd::Find { terms, kind, ext, min_size, under, dirs, files, sort, limit } => {
            query::find(&query::FindArgs { terms, kind, ext, min_size, under, dirs, files, sort, limit })?.print(json)
        }
        Cmd::Big { under, depth, files, name, kind, min_size, limit } => {
            query::big(&query::BigArgs { under, depth, files, name, kind, min_size, limit })?.print(json)
        }
        Cmd::Treemap { under, min_frac, out, no_open, serve, port } => {
            let a = treemap::Args { under, min_frac, out, open: !no_open };
            if serve { treemap::serve(&a, port)? } else { eprintln!("{}", treemap::run(&a)?) }
        }
        Cmd::Packages { name, version, exact, ecosystem, source, under, paths, limit } => query::packages(&query::PkgArgs {
            name, version, ecosystem, source, under, exact, paths, limit,
        })?
        .print(json),
        Cmd::Repos { name, dups, no_remote, vendored, under, sort, limit } => {
            repos::query(&repos::RepoArgs { name, under, dups, no_remote, vendored, sort, limit })?.print(json)
        }
        Cmd::Check { items, ecosystem, under, limit } => {
            let mut text = String::new();
            if items.is_empty() {
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            }
            for i in items {
                let p = std::path::Path::new(&i);
                text += &if p.is_file() { std::fs::read_to_string(p)? } else { i };
                text.push('\n');
            }
            query::check(&text, ecosystem.as_deref(), &under, limit)?.print(json)
        }
        Cmd::Types { kind, ext, limit } => query::types(kind.as_deref(), ext, limit)?.print(json),
        Cmd::Sniff { all, threads } => eprintln!("{}", sniff::run(all, threads)?),
        Cmd::Dups { min_size, include_caches, limit, threads } => dups::run(&dups::Args {
            min_size,
            include_caches,
            limit,
            threads,
            max_paths: if json { usize::MAX } else { 5 },
        })?
        .print(json),
        Cmd::Sql { query, write } => query::sql(&query, write)?.print(json),
        Cmd::Schema => println!("{}", db::schema_doc()),
        Cmd::Stats => query::stats()?.print(json),
        Cmd::Mcp => mcp::serve()?,
        Cmd::Skill { install } => {
            if install {
                let dir = PathBuf::from(std::env::var("HOME")?).join(".claude/skills/fff");
                std::fs::create_dir_all(&dir)?;
                let exe = std::env::current_exe()?;
                let body = format!("{SKILL}\nBinary on this machine: `{}` (use it when `fff` is not on PATH).\n", exe.display());
                std::fs::write(dir.join("SKILL.md"), body)?;
                eprintln!("installed {}", dir.join("SKILL.md").display());
            } else {
                print!("{SKILL}");
            }
        }
    }
    Ok(())
}
