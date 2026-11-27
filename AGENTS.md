# AGENTS.md

This is a guide for coding agents working on **fff**, a macOS-first local file indexer written in Rust.

Users and agents query the index through:
- the CLI;
- `fff mcp`, a stdio MCP server;
- `skills/fff/SKILL.md`.

Design rationale and measurements are in `DESIGN.md`; usage is in `README.md`.

## Build / test / run

```sh
cargo build --release            # binary: target/release/fff
cargo test --release
./target/release/fff scan  # ~1.5–5 min for a home folder; replaces the index atomically
./target/release/fff stats
FFF_HOME=/tmp/ff ./target/release/fff scan ~/src   # scratch index, leaves the real one alone
```

Test MCP without a client:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find","arguments":{"terms":["readme"],"limit":3}}}' \
  | ./target/release/fff mcp
```

## Layout

| File | What |
|---|---|
| `src/main.rs` | clap CLI. Each command calls a module and prints a `fmt::Table` (or a summary to stderr). |
| `src/scan.rs` | Parallel walker: rayon scope, 2×CPU threads. One writer thread over a crossbeam channel writes to a fresh `index.db.tmp`, which is renamed into place at the end. Opaque dirs (`OPAQUE`) are sized but their contents are not indexed; package manifests inside them go to `manifests`. |
| `src/packages.rs` | Package inventory, run at the end of scan. Reads manifests, dist-info dirs, Go module-cache and Gradle-cache dirs, lockfiles (npm/pnpm/yarn/Cargo/poetry/uv/go.mod/gradle) and project files (declared ranges, incl. pom.xml and libs.versions.toml), and fills `packages` (name, version, purl). `system()` is a packages-only pass over Homebrew Cellar/Caskroom, kegs, global npm/pip and `~/Library/Python`, `~/.cargo/.crates2.json` (rows with `dir` NULL): never make those scan roots, never run brew/npm/pip. |
| `src/versions.rs` | Version ranges as interval unions (PEP 440 / node-semver / Cargo; maven exact or `*`), offline, unit-tested; pre-release / post / Go pseudo-version tags are compared, not dropped: a query range matches resolved versions and overlaps declared ranges. Registered as the SQL functions `vmatch()` / `voverlap()` in `query::packages`. |
| `src/repos.rs` | Git repos, run at the end of scan: reads `.git/HEAD`, `config`, `packed-refs`, `commondir` directly (no git, never fetch). Remote URLs have credentials stripped and are normalised to `remote_key` for duplicate grouping; clones inside another repo under a hidden dir (`.external_modules`, `.terraform`) are `vendored`; plain sub-folder clones stay `repo`. |
| `src/db.rs` | Schema (`SCHEMA`, `INDEXES`, `CACHE_SCHEMA`), data dir, `schema_doc()` (what agents read before writing SQL). |
| `src/names.rs` | Sidecar name index (`names.bin`, `offsets.bin`, `ids.bin`): parallel memmem substring scan. |
| `src/query.rs` | find / big / types / packages / check / sql / stats, all returning `Table`. `check` parses a pasted compromised-package list (`parse_wants`, unit-tested) and matches it against `packages`. |
| `src/dups.rs` | Duplicates: size → inode → edge hash → BLAKE3, then an APFS clone check (getattrlist). Hash cache is in `hashes.db`. |
| `src/sniff.rs` | Magic-byte typing for files without a known extension. |
| `src/gitstate.rs` | What deleting a checkout would lose, read from `.git` only (never runs git): live worktrees, unpushed branches (remote refs, then remote reflogs only when needed), stash (loose or packed), staged changes (index TREE extension invalidated), merge/rebase in progress, tracked files edited vs `.git/index` (DIRC v2–4, skip-worktree included). Scan-time results go in `repos` (stats from the index); the Trash guard re-checks live with lstat. Unknown states (reftable, sha256, split/sparse index) give NULL, never "clean". |
| `src/treemap.rs` + `treemap.html` | Self-contained HTML treemap; the data is injected at `/*DATA*/null`. `--serve` adds a localhost server (std::net, token in `/*API*/null`) for reveal / open / trash, plus `remove_from_index`. |
| `src/mcp.rs` | MCP server (JSON-RPC 2.0, newline-delimited stdio, no SDK). |
| `src/fmt.rs` | `Table` → text or JSON (`to_json(true)` adds `*_human` twins for MCP). |
| `skills/fff/SKILL.md` | Agent skill, embedded in the binary (`fff skill [--install]`). |

## Invariants — don't break these

- **Never modify user files**, with one exception: `treemap --serve`'s Move to Trash. It uses the native macOS Trash (`NSFileManager trashItemAtURL`, so Put Back works), needs a per-run token and a localhost Host header, accepts only indexed non-root paths, and logs to `actions.log`. A git guard (`git_guard`) answers 409 with warnings when the path holds local git work (a main repo of outside worktrees, unpushed branches, stashes, edits, a worktree, a `.git`); the page asks again and resends with `force`, which is logged as `confirmed_despite`. It may print a `git worktree remove` hint, never run it. Nothing else deletes, and MCP never will.
- **Under `mcp`, stdout is protocol only.** Progress and logging go to stderr (`eprintln!`). Never use `println!` in library modules.
- **Dir ids are assigned parent-before-child.** Roll-ups depend on it: a top-down pass by increasing id, a bottom-up pass by decreasing id. Treemap and other consumers can `ORDER BY id`.
- Filter by subtree with a path range (`path >= '/x/' AND path < '/x0'`), never LIKE: the range uses the index.
- **Nested roots exist.** iCloud Drive (`~/Library/Mobile Documents`) is its own root (parent NULL) inside home's path range. Don't assume `dir_stats.depth` is comparable across roots.
- **Schema changes:** bump `db::SCHEMA_VERSION`, document new columns in `db.rs` (comments plus `NOTES`), and update the `schema` tool text if needed. The index is rebuilt on every scan, so no migrations are needed. `hashes.db` is persistent, so be careful there.
- `mtime` is in nanoseconds. `size` is the logical size and `alloc` is allocated bytes. iCloud-evicted files have `flags & 0x40000000` (dataless); never read them.
- No network calls. Package/CVE matching must work offline, or ask the user first, because package lists are private data.

## Conventions

- Errors use `anyhow`. Use plain functions, no traits or frameworks. Keep dependencies few: add one only when it replaces real code.
- New query features: add a function in `query.rs` returning `Table`, a CLI subcommand, an MCP tool (inputSchema + `readOnlyHint`), and a line in the SKILL.md table and the README.
- Performance matters: scanning is bound by lstat sys time, and queries should stay under 100 ms. Measure before and after (`/usr/bin/time -l`).
