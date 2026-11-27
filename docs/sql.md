# SQL over the index

The index is a plain SQLite file, `~/.local/share/fff/index.db`, rebuilt by every scan. `fff sql` opens it
read-only (only SELECT / WITH / PRAGMA run) unless you pass `--write`. The MCP `sql` tool is always read-only.

```sh
fff schema                      # the full schema with notes: the reference agents read
fff sql "SELECT count(*) FROM files"
fff sql --json "SELECT …"       # raw numbers for scripts
sqlite3 ~/.local/share/fff/index.db   # or any SQLite client
```

In text mode, columns named like sizes or times (`bytes`, `size`, `mtime`, …) are printed human-readable.

## Tables

| table | one row per | key columns |
|---|---|---|
| `dirs` | directory | `id` (parent-before-child), `parent`, `name`, `path`, `opaque`, `is_repo`, `repo_root` |
| `files` | file (outside opaque dirs) | `dir`, `name`, `ext`, `kind`, `size`, `alloc`, `mtime` (ns), `dev`, `ino`, `nlink`, `flags` |
| `dir_stats` | directory | subtree totals: `files`, `dirs`, `bytes`, `alloc`; `own_bytes` (files directly in the dir), `max_child`, `depth` |
| `packages` | package version × file it was read from | `ecosystem`, `name`, `version`, `purl`, `source` (installed / lockfile / declared), `path`, `dir` |
| `repos` | git checkout | `path`, `kind`, `remote`, `remote_key`, `branch`, `head`, `activity`, `at_risk`, `risk`, … |
| `manifests` | package manifest inside an opaque dir | `dir`, `path`, `ecosystem` |
| `dup_files` | duplicate file (created by `fff dups`) | `grp`, `file_id`, `hash`, `size`, `clone_id`, `private_size` |

Views:
- `v_files` is `files` plus the full `path` and `repo_root`;
- `v_dirs` is `dirs` joined with `dir_stats`.

## Rules of thumb

- **Subtrees: use a path range, not LIKE.** The range uses the index:
  `path = '/Users/me/src' OR (path >= '/Users/me/src/' AND path < '/Users/me/src0')`.
- **Opaque dirs** (`node_modules`, `.git`, `.venv`, `target`, caches) are in `dirs`, with their size in `dir_stats`, but their files
  are not in `files`.
- **`mtime` is in nanoseconds:** `date(mtime/1e9, 'unixepoch')`.
- **`size` is logical bytes and `alloc` is bytes on disk.** Hardlinks are counted once per name.
- **iCloud placeholders:** `flags & 0x40000000` (dataless) means the file is in iCloud but not downloaded.
- **Nested roots:** iCloud Drive is its own root inside home's path range, so `depth` is per root.
- **`packages.dir` IS NULL** for Homebrew and global installs. Use a LEFT JOIN to `dirs`.

## Recipes

```sql
-- largest files modified in the last 30 days
SELECT path, size, date(mtime/1e9,'unixepoch') day FROM v_files
WHERE mtime > (strftime('%s','now') - 30*86400) * 1e9 ORDER BY size DESC LIMIT 20;

-- rebuildable junk by type (node_modules, target, .venv, …)
SELECT name, count(*) n, sum(bytes) bytes FROM v_dirs
WHERE opaque AND name <> '.git' GROUP BY name ORDER BY bytes DESC LIMIT 15;

-- bytes per kind under one folder
SELECT f.kind, count(*) n, sum(f.size) bytes FROM files f JOIN dirs d ON d.id = f.dir
WHERE d.path = '/Users/me/Documents' OR (d.path >= '/Users/me/Documents/' AND d.path < '/Users/me/Documents0')
GROUP BY 1 ORDER BY 3 DESC;

-- directories over 1 GB untouched for a year
SELECT v.path, v.bytes, date(max(f.mtime)/1e9,'unixepoch') newest
FROM v_dirs v JOIN files f ON f.dir = v.id
WHERE v.bytes > 1e9 AND v.own_bytes > 0.5*v.bytes
GROUP BY v.id HAVING max(f.mtime) < (strftime('%s','now')-365*86400)*1e9
ORDER BY v.bytes DESC;

-- disk images and installers in Downloads
SELECT path, size FROM v_files
WHERE kind = 'diskimage' AND path >= '/Users/me/Downloads/' AND path < '/Users/me/Downloads0' ORDER BY size DESC;

-- files in iCloud that are not downloaded
SELECT count(*), sum(size) FROM files WHERE flags & 0x40000000;

-- git repos with the most rebuildable bytes
SELECT r.path, sum(s.bytes) bytes FROM repos r JOIN dirs d ON d.repo_root = r.dir AND d.opaque AND d.name <> '.git'
JOIN dir_stats s ON s.dir = d.id GROUP BY r.dir ORDER BY bytes DESC LIMIT 10;

-- after `fff dups`: the folders holding the most duplicate bytes
SELECT d.path, sum(u.private_size) bytes FROM dup_files u JOIN files f ON f.id = u.file_id JOIN dirs d ON d.id = f.dir
GROUP BY d.id ORDER BY bytes DESC LIMIT 15;
```

[packages.md](packages.md) and [repos.md](repos.md) have recipes for those tables.
