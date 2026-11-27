# fff — fast find files

A fast local index of every file on your Mac, for you and for your AI agents.

One scan (a couple of minutes for a home folder) builds a SQLite index. After that, these questions take milliseconds:

- **Where is that file?** Name search over all of `$HOME` and iCloud Drive in 10–40 ms.
- **Where did my disk go?** Large directories, largest files, a clickable treemap, duplicates, and how much is rebuildable `node_modules` / `target` / `.venv`.
- **Are we hit by this advisory?** Paste a list of compromised package versions and see every installed copy, lockfile pin and project range that could pull one in. This covers npm, PyPI, Maven/Gradle, Cargo, Go and Homebrew, offline.
- **Which git checkouts can I delete?** Duplicate clones and worktrees, with what deleting each one would lose: unpushed branches, stashes, staged or edited files, and worktrees that depend on it.

Everything stays on your machine. fff never makes network calls, never runs `git`, `brew`, `npm` or `pip`, and never changes your files. The single exception is the treemap's *Move to Trash* button, which you click yourself; Put Back works.

macOS only (it uses APFS clone detection, `st_flags` for iCloud placeholders and the native Trash). Written in Rust: one binary, no daemon.

---

## Contents

- [Install](#install)
- [A quick tour](#a-quick-tour)
  - [Find files](#find-files)
  - [Where did my disk go?](#where-did-my-disk-go)
  - [Supply-chain incident: are we affected?](#supply-chain-incident-are-we-affected)
  - [Git repos and duplicate checkouts](#git-repos-and-duplicate-checkouts)
  - [SQL for everything else](#sql-for-everything-else)
- [The treemap](#the-treemap)
- [Use it from AI agents](#use-it-from-ai-agents)
- [Command reference](#command-reference)
- [How it works](#how-it-works)
- [Safety and privacy](#safety-and-privacy)
- [Limits](#limits)
- [License](#license)

More detail:
- [docs/packages.md](docs/packages.md): package sources and version ranges.
- [docs/repos.md](docs/repos.md): what the git check reads and how it was validated.
- [docs/sql.md](docs/sql.md): the schema and query recipes.
- [DESIGN.md](DESIGN.md): the original research and measurements.
- [AGENTS.md](AGENTS.md): a guide for coding agents working on this repo.

---

## Install

You need Rust 1.85 or newer (edition 2024).

```sh
git clone https://github.com/jverhoeks/fff.git
cd fff
cargo build --release
cp target/release/fff ~/.local/bin/      # or anywhere on your PATH

fff scan     # first scan: ~1.5–5 min for a home folder
fff stats
```

`scan` indexes `$HOME` and iCloud Drive. It skips the rest of `~/Library`, which is mostly app caches and triggers macOS privacy prompts.
It then reads package versions from Homebrew and global npm/pip installs, without indexing those folders. Rerun `scan`
whenever you want fresh results. It builds the new index in a temp file and swaps it in, so queries keep working during a scan.

```sh
fff scan ~/src ~/Downloads              # only these roots
fff scan --library                      # include all of ~/Library
fff scan --exclude ~/VMs                # skip a directory
FFF_HOME=/tmp/ff fff scan ~/src         # a scratch index; leaves the real one alone
```

Data lives in `~/.local/share/fff` (override with `FFF_HOME`).

> To scan folders like `~/Desktop` or `~/Library/Mail` without a prompt for each one, give your terminal **Full Disk Access**
> (System Settings → Privacy & Security). `scan` reports how many directories it could not read.

---

## A quick tour

The examples come from a small demo home folder. Some wide columns are trimmed. Every command takes `--json` for
scripts and agents; JSON gives raw byte counts and nanosecond timestamps.

### Find files

All terms must appear in the name (case-insensitive substrings). fff searches a compact name buffer in parallel,
so there is no full-text index to keep up to date.

```console
$ fff find invoice
path                                              size  kind      modified
/Users/me/Documents/invoices/                     1.0M  dir
/Users/me/Documents/invoices/invoice-2025-04.pdf  293K  document  2026-11-27 17:03
/Users/me/Documents/invoices/invoice-2025-03.pdf  781K  document  2026-11-27 17:03
/Users/me/Downloads/invoice-2025-03.pdf           781K  document  2026-11-27 17:03
4 shown; name scan matched 3 files, 1 dirs in 4 ms
```

You can filter by kind, extension, size and folder, and choose the sort order:

```sh
fff find --kind slides -n 20              # recent decks
fff find --kind video --sort size         # biggest videos
fff find -e pdf -u ~/Downloads --min-size 10M
fff find budget 2026 --files --sort name
```

Kinds: `document slides sheet image video audio archive diskimage code data font binary ebook mail`. Run `fff sniff`
to type files without an extension by their magic bytes.

### Where did my disk go?

The scan computes subtree totals once, so `du`-style views are instant at any depth:

```console
$ fff big -u ~ -d 2 --min-size 1K
path                          size  files   own  biggest child  type
/Users/me/src                  10M    130    0B            56%
/Users/me/src/tool            5.8M     41   63B           100%  git
/Users/me/Downloads           3.1M      2  3.1M             0%
/Users/me/src/api             2.9M     36  126B            99%  git
/Users/me/src/webapp          1.6M     50  356B            98%  git
/Users/me/Documents           1.1M      3 1008B           100%
/Users/me/Documents/invoices  1.0M      2  1.0M             0%
/Users/me/old/webapp-copy      29K     37  356B            99%  git
```

Without `-u`, `fff big` lists the **heavy** directories: big in their own right, not just because they hold one big child.
These are usually the places worth looking at.

```sh
fff big                        # heavy dirs anywhere (≥ 100M)
fff big --name node_modules    # every node_modules, biggest first (also: target, .venv, DerivedData)
fff big --files --min-size 1G  # largest files
fff types                      # bytes per kind;  --ext for per extension
fff repos -s junk              # git repos by rebuildable build/deps bytes
fff treemap                    # the picture (see below)
```

**Duplicates.** `dups` narrows candidates in stages:
1. same size;
2. different inode (hardlinks are not duplicates);
3. a hash of the first and last 4 KiB;
4. a full BLAKE3 hash.

It also detects APFS clones: copies that share blocks, so deleting one frees nothing. Hashes are cached by inode, size and mtime, so later runs are fast.

```console
$ fff dups --min-size 100K
group  size  copies  reclaimable  path
    1  781K       2         781K  /Users/me/Downloads/invoice-2025-03.pdf
                                  /Users/me/Documents/invoices/invoice-2025-03.pdf
1 duplicate groups; 1 redundant copies (781K), reclaimable after APFS clones 781K; 0 hardlinked names skipped
```

### Supply-chain incident: are we affected?

A worm like Shai-Hulud, or a hijacked maintainer account, can publish bad package versions. When that happens you want to know quickly whether any of
them are on your machine. Paste the advisory's list as it is:

```console
$ fff check debug@4.4.2 chalk@5.6.1
status         ecosystem  name   version / range  listed  path
INSTALLED      npm        chalk  5.6.1            5.6.1   /Users/me/src/webapp/node_modules/chalk/package.json
INSTALLED      npm        debug  4.4.2            4.4.2   /Users/me/old/webapp-copy/node_modules/debug/package.json
LOCKFILE       npm        chalk  5.6.1            5.6.1   /Users/me/old/webapp-copy/package-lock.json
LOCKFILE       npm        chalk  5.6.1            5.6.1   /Users/me/src/webapp/package-lock.json
could install  npm        chalk  ^5.0.0           5.6.1   /Users/me/old/webapp-copy/package.json
could install  npm        chalk  ^5.0.0           5.6.1   /Users/me/src/webapp/package.json
could install  npm        debug  ^4.3.0           4.4.2   /Users/me/old/webapp-copy/package.json
could install  npm        debug  ^4.3.0           4.4.2   /Users/me/src/webapp/package.json
2 installed, 2 in lockfiles, 4 project ranges could install a listed version, 0 unclear (tags/urls). 2 of 2 listed packages hit; …
```

- **INSTALLED**: the package is on disk. fff looks in:
  - `node_modules`, `.venv` and site-packages;
  - `~/.m2`, the Gradle and Go module caches, the cargo registry;
  - Homebrew, global npm/pip, and `cargo install`.
- **LOCKFILE**: pinned in a lockfile, so the next `npm ci` or `uv sync` installs it.
- **could install**: a project file declares a range that includes the bad version, so a fresh resolve could pick it.

The list can be messy. fff reads these formats:
- `name@1.2.3`, `name 1.2.3, 1.2.4`, `name (1.2.3)`, `name: 1.2.3`, `name==1.2.3`, purls, and bare names;
- numbered and bulleted lists, markdown tables and links, and smart quotes.

Anything it can't read is listed as NOT CHECKED rather than dropped.

```sh
pbpaste | fff check                    # straight from an advisory page
fff check iocs.txt                     # a file, one or more entries per line
fff check -e pypi 'requests==2.32.0'   # limit to one ecosystem
```

For one package, `packages` shows every version present and where it is:

```console
$ fff packages pandas -x -v 2.1.0
ecosystem  name    version / range  status               path
pypi       pandas  2.1.0            installed            /Users/me/src/api/.venv/lib/python3.12/site-packages/pandas-2.1.0.dist-info
pypi       pandas  2.1.0            lockfile             /Users/me/src/api/requirements.txt
pypi       pandas  >=2.0,<2.3       declared, allows it  /Users/me/src/api/pyproject.toml
1 installed, 1 in lockfiles, 1 project files whose range could resolve to it
```

`-v` takes versions and ranges: `2.1.0`, `'2.*'`, `'^2.1'`, `'~2.1'`, `'>=2.1 <2.3'`, `'1.x || 3.x'`, `'~=2.1'`, or `'/regex/'`.
Ranges follow each ecosystem's own rules (PEP 440 and Poetry, node-semver, Cargo, Maven), including prereleases and Go pseudo-versions.
fff has no vulnerability database of its own. It answers "where is X" for the versions you give it. See
[docs/packages.md](docs/packages.md) for every source it reads.

### Git repos and duplicate checkouts

The scan reads each `.git` directly: remote, branch, HEAD and last activity. It also checks **what deleting that checkout would
lose**.

```console
$ fff repos -s path        # (head and last-activity columns trimmed)
path                       kind      remote                             branch      size  build/deps  local work
/Users/me/old/webapp-copy  repo      https://github.com/example/webapp  main         29K         35B  no sign of local work
/Users/me/src/api          repo                                         main        2.9M        2.9M  no remote: 1 branch exist nowhere else; 1 tracked file edited or deleted
/Users/me/src/tool         repo      https://github.com/example/tool    main        5.8M        5.7M  main repo of 1 worktree in /Users/me/src (1) (deleting it breaks them)
/Users/me/src/tool-fix     worktree  https://github.com/example/tool    fix/parser  245B          0B  no sign of local work; worktree: drop with `git worktree remove`, not the Trash
/Users/me/src/webapp       repo      git@github.com:example/webapp.git  main        1.6M        1.5M  1 unpushed branch (feature/login)
5 repos (1 vendored/worktrees/submodules, 1 without a remote, 3 with local work that deleting would lose; untracked files not checked)
```

`--dups` groups checkouts of the same project. fff normalises the remote URL, so `git@github.com:example/webapp.git` and
`https://github.com/example/webapp` count as the same project:

```console
$ fff repos --dups
remote                     copies  kind      path                       branch      size  build/deps  local work
github.com/example/webapp       2  repo      /Users/me/old/webapp-copy  main         29K         35B  no sign of local work
github.com/example/webapp       2  repo      /Users/me/src/webapp       main        1.6M        1.5M  1 unpushed branch (feature/login)
github.com/example/tool         2  repo      /Users/me/src/tool         main        5.8M        5.7M  main repo of 1 worktree in /Users/me/src (1) (deleting it breaks them)
github.com/example/tool         2  worktree  /Users/me/src/tool-fix     fix/parser  245B          0B  no sign of local work; worktree: drop with `git worktree remove`, not the Trash
1 remotes are cloned more than once (2 full clones, 29K beyond the largest clone of each); 1 worktrees use 245B (0B of it build/deps).
Before deleting: 2 copies show no sign of local work (29K, 35B of it build/deps). …
```

Clean up in this order:

1. **Free build output first.** The `build/deps` bytes (`target`, `node_modules`, `.venv`, …) can be rebuilt and are usually most of the
   size. `fff repos -s junk` and `fff big --name target` find them.
2. **Drop worktrees with `git worktree remove <path>`**, not the Trash. Their branches live in the main repo.
3. **Never delete a repo marked "main repo of N worktrees"**: its worktrees stop working.
4. **"no sign of local work"** means `.git` holds nothing that exists only on this machine. Untracked files are *not* checked, so look before you delete.

`fff repos --no-remote` lists repos whose history exists nowhere else. [docs/repos.md](docs/repos.md) explains each
check and how it was validated against `git` on real repos.

### SQL for everything else

For anything the commands don't cover, query the index with SQL. It is plain SQLite, opened read-only unless you pass `--write`:

```sh
fff schema         # tables, columns and notes (agents read this before writing SQL)

# what kind of rebuildable junk takes the most space
fff sql "SELECT name, count(*) n, sum(bytes) bytes FROM v_dirs WHERE opaque AND name <> '.git'
               GROUP BY name ORDER BY bytes DESC LIMIT 10"

# directories over 1 GB whose files were all last modified more than a year ago
fff sql "SELECT v.path, v.bytes, date(max(f.mtime)/1e9,'unixepoch') newest
               FROM v_dirs v JOIN files f ON f.dir = v.id
               WHERE v.bytes > 1e9 AND v.own_bytes > 0.5*v.bytes
               GROUP BY v.id HAVING max(f.mtime) < (strftime('%s','now')-365*86400)*1e9
               ORDER BY v.bytes DESC"
```

[docs/sql.md](docs/sql.md) has more recipes and the full schema.

---

## The treemap

```sh
fff treemap              # all scan roots → a self-contained HTML page, opens in your browser
fff treemap -u ~/src     # one subtree, more detail
fff treemap --serve      # the same, plus right-click actions
```

A squarified treemap in the style of WinDirStat:
- Click a box to zoom in. Esc or Backspace goes back up.
- Boxes are coloured by kind. Git repos and rebuildable dirs (`node_modules`, `target`, …) are marked.
- The page has no external dependencies, so you can save it or share it.

With `--serve`, fff runs a server on `127.0.0.1`, and right-clicking a box offers **Reveal in Finder**, **Open** and **Move to Trash**:

- Every request needs a random per-run token and a localhost `Host` header, so other web pages can't call it.
- Only paths in the index can be acted on, and scan roots can't be trashed.
- Items go to the macOS Trash, so **Put Back** works. The space is freed when you empty the Trash.
- **Git guard.** Before trashing, the server re-reads `.git` for every checkout at or under the path. If it finds work that exists nowhere
  else, the page asks a second time and names that work. Cases include:
  - a main repo whose worktrees live elsewhere;
  - unpushed branches, stashes, and staged or edited files;
  - trashing a worktree or a `.git` dir.

  Folders inside a working tree, like `target/` or `node_modules`, go to the Trash without the second question.
- Every action is appended to `actions.log` in the data dir, including any warning you confirmed.

---

## Use it from AI agents

fff is built for agents to use: queries are fast, output is compact, and the schema is documented so they can write SQL.

**MCP server** (Claude Code, Claude Desktop, or any MCP client). Tools: `find`, `big`, `types`, `packages`, `check_packages`,
`repos`, `dups`, `sql` (read-only), `schema`, `stats`, `scan`. None of them can change or delete files.

```sh
claude mcp add fff -s user -- "$(which fff)" mcp
```

For Claude Desktop, add this to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{ "mcpServers": { "fff": { "command": "/abs/path/to/fff", "args": ["mcp"] } } }
```

**Skill**, for agents that run the CLI: `fff skill --install` writes `~/.claude/skills/fff/SKILL.md`.

Then ask things like:

> *"What's eating my disk under ~/src, and how much of it is rebuildable?"*
> *"Here's the Shai-Hulud IOC list — are any of these installed or pinned on this machine?"*
> *"Which of my duplicate checkouts can I delete without losing work?"*
> *"Find the slides I made about pricing last month."*

---

## Command reference

| Command | What it does |
|---|---|
| `scan [ROOTS…]` | Rebuild the index. `--library`, `--no-icloud`, `--no-system`, `--exclude DIR`, `--full` (index inside node_modules etc.), `--cross-devices` |
| `find TERMS…` | Name search. `-k KIND`, `-e EXT`, `--min-size`, `-u DIR`, `--dirs`/`--files`, `--sort mtime\|size\|name`, `-n` |
| `big` | Heavy dirs. `-u DIR [-d N]` du-like, `--name NAME`, `--files [-k KIND]`, `--min-size` (default 100M) |
| `treemap` | HTML treemap. `-u DIR`, `--serve [--port]`, `-o FILE`, `--no-open` |
| `types` | Files and bytes per kind; `--ext` for per extension |
| `dups` | Duplicate files. `--min-size` (default 1M), `--include-caches` |
| `sniff` | Type extension-less files by magic bytes |
| `packages [NAME]` | Package versions: installed, lockfile, declared. `-x` exact name, `-v VERSION\|RANGE\|/regex/`, `-e ECOSYSTEM`, `-s SOURCE`, `--paths`, `-u DIR` |
| `check [FILE\|ITEMS…]` | Check a compromised-version list (from stdin, a file or arguments). `-e`, `-u` |
| `repos [NAME]` | Git repos with the local-work check. `--dups`, `--no-remote`, `--vendored`, `-s activity\|size\|junk\|path`, `-u DIR` |
| `sql "SELECT …"` | SQL over the index; `--write` allows changes |
| `schema` | Schema with notes |
| `stats` | Index summary and freshness |
| `mcp` | MCP server on stdio |
| `skill [--install]` | Print or install the agent skill |

Every query command takes `--json`.

---

## How it works

- **Scan.** A parallel walker (rayon, 2× CPU threads) calls `lstat` on everything. It streams rows over a channel to a single SQLite
  writer, which writes `index.db.tmp`; the file is renamed into place when the scan ends. A home folder with 1.4M files and 520 GB takes
  about 70–150 s, limited by kernel `lstat` time.
- **Opaque dirs.** `.git`, `node_modules`, `.venv`, a `target/` next to a `Cargo.toml`, caches, `~/.m2` and similar dirs are *sized*, but
  their contents are not indexed. That keeps the index small and the results useful. Package manifests inside them are still
  read for the package inventory. `scan --full` indexes everything except `.git`.
- **Subtree totals.** Directory ids are assigned parent-before-child, so a single bottom-up pass computes every directory's
  totals. `big` and `treemap` read them directly.
- **Name search.** All names go into one flat buffer (`names.bin`), which a parallel `memmem` scan searches:
  10–40 ms for 1.4M names, with no index to keep in sync.
- **Packages and repos.** After the walk, fff reads manifests, lockfiles, project files and `.git` metadata into the
  `packages` and `repos` tables.
- **Storage.**
  - `index.db`: rebuilt on every scan; typically a few hundred MB for a home folder.
  - The name buffers.
  - `hashes.db`: the duplicate hash cache, which survives rescans.

The schema is in [docs/sql.md](docs/sql.md). Design notes and measurements are in [DESIGN.md](DESIGN.md).

---

## Safety and privacy

- **Local only.** No network calls; package matching works fully offline. Your package inventory is a map of the software you
  run, and fff never sends it anywhere.
- **Read-only.** fff reads metadata (`lstat`), manifests and `.git` files. It never writes to your files and never runs
  `git`, `brew`, `npm`, `pip`, `go`, `mvn` or `gradle`. Everything under `mcp` is read-only, `sql` included.
- **One delete path: the treemap's *Move to Trash*.** You click it yourself and it needs the per-run token. It goes to the
  macOS Trash (Put Back works), passes the git guard, and is logged.
- **iCloud.** Files that are in iCloud but not downloaded (dataless) are indexed by name and size but never read, so neither
  `scan` nor `dups` triggers downloads. fff re-checks this just before it reads any file.
- **Credentials.** Remote URLs are stored with any `user:token@` part removed.

---

## Limits

- **The git check reads `.git` only.**
  - Untracked files are not checked.
  - It compares tracked files by size and mtime: an edit that keeps both is missed.
  - A branch counts as pushed if its tip was ever on a remote-tracking ref, so stale refs (a force-push you never fetched) can hide work.
  - A submodule's unpushed commits show on the submodule's row, not on the superproject's.

  [docs/repos.md](docs/repos.md) has the details.
- **No vulnerability database.** `check` and `packages` answer "where is this version", not "is this version vulnerable".
- **Not covered yet:** conda environments, `build.gradle` without a lockfile, Go binaries' embedded build info, jars inside apps,
  an `/Applications` inventory, the `~/.npm` cache, and go.mod `replace` lines.
- **Name search compares bytes.** A name stored decomposed (NFD, as some zip tools and older Finder copies write `café`) is not
  found by a query typed precomposed (NFC).
- **No incremental updates** (FSEvents). Rerun `scan`.
- **macOS only.**

## License

[Apache License 2.0](LICENSE).
