---
name: fff
description: Find files on this Mac, explain where disk space goes and inventory installed package versions, using the local fff index (names, sizes, kinds, directory subtree totals, duplicates, npm/pypi/maven/cargo/go packages and Homebrew, SQL). Use when the user asks where a file is, what is taking up space, which directories are large, about node_modules / target / caches, duplicate files, git repos and duplicate checkouts, "files like X modified recently", which versions of a library are installed (CVE exposure), or whether packages from a supply-chain attack advisory (compromised npm/pypi versions) are installed here.
---

# fff (fast find files)

`fff` keeps a SQLite index of the files on this Mac, rebuilt by `fff scan` (about 2–6 min for a home folder).
Queries take milliseconds, so prefer it over `find`, `du` or `mdfind`.
Add `--json` to any query command for machine-readable output: raw byte counts and ns timestamps.

If the `fff` MCP server is connected, use its tools instead. They have the same names: find, big, types, packages, repos, dups, sql, schema, stats, scan (and `check_packages` for `fff check`).

## Pick the command

| Question | Command |
|---|---|
| Where is file X? | `fff find budget 2026 --json` (all terms are substrings of the name) |
| Recent decks / large videos | `fff find --kind slides -n 20`, `fff find --kind video --sort size` |
| What fills my disk? | `fff big` (heavy directories), then `fff big --under ~/src --depth 2` |
| All node_modules / target dirs | `fff big --name node_modules`, `fff big --name target` |
| Largest files | `fff big --files --min-size 1G` |
| Space by type | `fff types`, `fff types --kind image` |
| Is package X (version Y) installed / used anywhere? | `fff packages lodash`, `fff packages log4j-core --paths`, `fff packages pandas -x -v 2.1.0` (installed, pinned, and project ranges that allow it); ranges: `-v '2.*'`, `'^2.1'`, `'>=2.1 <2.3'`, `'~=2.1'`; regex: `-v '/2\.1\..*/'` |
| Supply-chain incident: are any of these compromised packages here? | `pbpaste \| fff check` or `fff check list.txt` or `fff check '@ctrl/tinycolor@4.1.1' 'debug@4.4.2'`: lists INSTALLED copies, LOCKFILE pins, and project files whose range *could install* a listed version. Paste the advisory list as-is (`name@1.2.3`, `name 1.2.3, 1.2.4`, `name==1.2.3`, purls, bare names = any version). Read the note: it says which listed packages are present only at other versions, and what the index does not cover (the ~/.npm cache, build.gradle without a lockfile, conda, Go binaries). Homebrew formulae/casks, global npm/pip, cargo-installed binaries, the Go module cache, ~/.m2 and the Gradle cache are included (`-e brew` for Homebrew). Maven `*` rows are pom.xml dependencies whose version comes from a parent/BOM: any version could land there. |
| Git repos / duplicate checkouts | `fff repos` (remote, branch, last activity, size), `fff repos --dups` (same remote checked out more than once; vendored clones inside another repo's hidden dir, e.g. `.external_modules`, are left out unless `--vendored`), `fff repos --no-remote` (local-only work), `fff repos -s junk` (rebuildable build/deps per repo). The `local work` column says what deleting a checkout would lose ("main repo of N worktrees" = deleting it breaks them; unpushed branches, stashes, staged changes, edited tracked files); untracked files are not checked, so say so. Advise: free build/deps first, drop worktrees with `git worktree remove`, never delete a main repo of worktrees. |
| Duplicates | `fff dups --min-size 10M` (first run hashes; minutes) |
| Visual overview for the user | `fff treemap [--under DIR]` (opens HTML) |
| Anything else | `fff schema`, then `fff sql "SELECT … LIMIT 50" --json` |
| Is the index fresh? | `fff stats` |

## SQL tips

- Use the views `v_files` and `v_dirs`.
  - `v_files` has a full `path`.
  - `v_dirs` has subtree totals: `bytes`, `files`, `dirs`, `max_child`.
- Filter by subtree with a range, not LIKE: `path >= '/Users/me/src/' AND path < '/Users/me/src0'`.
- `mtime` is nanoseconds since the epoch: `mtime > (strftime('%s','now','-7 days') * 1000000000)`.
- `opaque = 1` marks a dir that is sized but whose contents are not indexed: node_modules, .git, target, .venv, caches.
- `packages` has one row per (package version, file it was read from): ecosystem, name, version, purl, source (installed|lockfile|declared), path. For `declared` rows `version` is a range (`>=2.0,<3`, `^2.1`, `*`): use `fff packages NAME -x -v X.Y.Z` (or a range like `2.*`) to test them, not SQL `=`.
- `manifests` lists the package manifests found inside those opaque dirs (npm/pypi/maven/cargo).

## Rules

- Results reflect the last scan. Mention the scan time if it matters.
- fff never modifies or deletes files. If the user wants to clean up, show the paths and sizes and let them decide.
- Report sizes in human units (the JSON rows from MCP include `*_human` fields).
