# fff — design and storage research

> These are the original research and design notes, written before any code (2026-11-23), plus measurements
> added while building. The code has moved on in places; [README.md](README.md) and [AGENTS.md](AGENTS.md) describe
> what fff does today.

Goal: take the ideas of repoidx (an earlier tool of mine) (local index of
every git repo) and of [Lisorto](https://lisorto.app/) (local file
organiser + search), and build a **simple Rust app** that indexes *all*
files on the Mac, searches them fast, and knows **relations** between files,
especially "this file belongs to git repo X, at branch/tag/commit Y".

---

## 1. Recommendation (TL;DR)

1. **A new Rust tool in this folder, not a rewrite of repoidx.** repoidx is Go
   + pure-Go SQLite and works. The new tool covers all files; it detects
   repos itself (cheap, it walks past every `.git` anyway) and can `ATTACH`
   repoidx's `~/.local/share/repoidx/index.db` read-only for the rich repo
   metadata (groups, sync state, identities). Porting repoidx into it is a
   later, optional step.
2. **One SQLite file is the system of record** (`rusqlite`, bundled SQLite,
   WAL). Files, directories, repos, blobs, refs, packages and relations are
   plain tables. No graph database: no query needs more than 2 hops or any
   recursion.
3. **Name search needs no index:** do a brute-force parallel scan of a
   compact name buffer (see §4, measured at 20–40 ms for all 4.3M names).
   Content search uses **SQLite FTS5** in the same file for v1. Move to
   **Tantivy** only if content volume outgrows it.
4. **Git relations: yes for tiers 0–2, opt-in for tier 3.** Membership plus
   tracked or modified status, and identical content across repos, are
   nearly free. Branch and tag tips are fine when keyed on distinct blobs
   with a ref bitmap (1.2–5× the index). Stored naively as (path, ref), they
   explode to 13–77× the index. Full history is the stretch: store only
   "commit touched path" deltas, opt-in per repo. Measured numbers are in §5.
5. **Yes, also index installed software and dependencies for CVE checks**
   (§5b). It is the same relation model: package@version → where it is
   installed or declared. It combines with T2: "vulnerable lockfile on tag
   v1.2".

---

## 2. Scope: which part of Lisorto

Lisorto is mainly a **sorter** (Spaces, AutoPilot, clear names via AI,
duplicates, undo journal) with a **single-file local search index** (names
plus OCR'd text, Shift-Cmd-Space). It has **no relations, tags or graph**.
That is where we differ.

| Tier | What | Lisorto has | Here |
|---|---|---|---|
| v1 | Index all files, name + content search, CLI | yes | **design target** |
| v2 | Relations: repo, git status, blob identity, refs, duplicates | no | **design target** |
| v3 | Live updates (FSEvents), daemon, launcher UI / TUI | yes | later |
| v4 | Sort/rename with journal + undo (Lisorto's safety model: propose → approve → move, never delete/overwrite) | yes | later |
| v5 | OCR (Apple Vision), image content, embeddings / "ask your files" | yes | later, optional |

Shortcut worth trying for v1 content search on macOS: Spotlight already
extracts text. `mdfind` / `MDQuery` can serve as a content backend while we
build our own extraction.

---

## 3. The queries that decide the database

| # | Query | Shape |
|---|---|---|
| Q1 | substring / fuzzy file name search | scan or n-gram index over ~4M names |
| Q2 | full-text in content (docs, PDFs, READMEs) | inverted index, BM25 |
| Q3 | file → repo, tracked / modified / ignored / untracked | 1 hop (dir prefix → repo) |
| Q4 | blob id → all paths with identical content (across repos, Downloads, backups) | 1 hop, index on hash |
| Q5 | which branches / tags contain this file (this blob) | bounded walk up trees: depth = path depth, ≤ ~15 |
| Q6 | which commits touched this path | 1 hop on a delta table (opt-in) |
| Q7 | incremental update: what changed since last scan | dir mtime + FSEvents event id; git index mtime + refs hash (repoidx trick) |
| Q8 | filters: by type, size, age, repo group, customer | B-tree indexes |

Conclusion: this is a **relational workload with a few joins**. Graph
engines win on deep or many-hop traversals and worst-case-optimal joins over
cyclic patterns. We have neither, so their extra weight doesn't pay off
(see §6 on the papers).

---

## 4. Measurements on this Mac

Command: `find ~ -xdev`, excluding `~/Library`, `node_modules`, `.git`,
`.terraform`, `target` and `.venv`.

| | value |
|---|---|
| entries (files + dirs) | **4,297,166** (3.74M files) |
| distinct directories | 522,623 |
| full paths, total bytes | 521 MB |
| bare names, total bytes | **93 MB** (5.6× smaller → store a parent-id tree, not full paths) |
| `find` cold-ish walk | 28 s (single `find`; a parallel `getattrlistbulk` walker will be much faster) |
| `rg -i invoice` over all 93 MB of names | **20–40 ms** (1121 hits) |
| `grep -i` same | 1.9 s (shows SIMD `memchr`/`memmem` matters) |
| repoidx index | 591 repos, 210,417 tracked files, 15 MB db |

So for Q1, a contiguous name buffer scanned with `memchr::memmem` plus
`rayon`, or `nucleo` for fuzzy matching, is fast enough. A trigram index
(Russ Cox / plocate style) should only pay off at a much larger size or for
regex-heavy use. That is an estimate; benchmark before adding one.
For a one-shot CLI, keep the name buffer as a rebuildable, mmapped sidecar
(`names.bin` + offsets). Loading 4M rows out of SQLite on every call costs
noticeably more.

---

## 4b. File types: extension, magic bytes, Magika

Goal: "all pptx / pdf / video" in milliseconds.

Measured (3.74M regular files, 259 GB):

| | value |
|---|---|
| distinct extensions | 1,590 |
| files without an extension | 234,419 (6.3%), but **26 GB**, the biggest "type" by bytes |
| top extensions by count | py 855k, html 568k, json 296k, pyc 249k, svg 212k, h 176k, rs 116k |
| office / docs | pdf 1,280 · xlsx 1,178 · docx 134 · pptx 123 · key 184 |
| media | png 29k · jpg 17k · mp4 1,050 · heic 315 · mov 211 |
| random cold 4 KB header read | **~5 ms/file** single-threaded, measured alongside the hashing run, so pessimistic. That would be ~5 h for everything |
| `file --mime-type` vs extension, 3,000-file sample | the extension is right for almost everything. libmagic is often *less* specific for text: `.py` → `text/plain` (183 of 640) and some `.html` → python |

Design: three stages, cheapest first. The type is stored in `files.kind`
with an index, so "all pptx" is an index range scan.

1. **Extension → kind** (static table: pdf→document/pdf, pptx→slides, …).
   It covers ~94% of files at zero I/O cost and is done during the walk.
2. **Magic bytes** (`infer` / `file-format` crates, ~8–64 bytes). Use it for
   files with no extension and for containers. **pptx, docx and xlsx are all
   ZIP files.** They differ by their entry names (`ppt/`, `word/`, `xl/`),
   and `infer` checks this. Runs in a background pass, in parallel.
3. **Magika** (Google; ICSE 2025; Rust crate `magika` 1.x; a deep-learning
   model run on ONNX Runtime). ~99% average F1 over 100+ types, and much
   better than libmagic on text and code. Google says "hundreds of files per
   second", so it is **more accurate, not faster**. Use it lazily for the
   ~200k unknown files or files whose extension and magic bytes disagree,
   e.g. a `.pdf` that is really HTML. Also useful as a security signal.

Rules:
- **Never read dataless iCloud files.** Check the `SF_DATALESS` flag from the
  stat call first. Otherwise sniffing a header downloads the file.
- Store `kind_source` (ext / magic / magika) so stages can be re-run.

---

## 4c. Duplicates

Measured on the same 3.74M files. Method: group by size, then a BLAKE2
hash of the first and last 16 KB. These are *probable* duplicates; a full
hash still has to confirm them.

| | value |
|---|---|
| extra hardlink names (same inode, not duplicates) | 53,658 |
| files sharing a size with another file | **3.57M (95%)**: size alone is a weak filter for small files |
| partial-hash pass, 16 threads, Python | **43 min**: the naive pipeline is too slow to run over everything |
| probable duplicate groups / files | 390k groups, 2.4M files |
| probable wasted bytes | **61 GB of 259 GB** |
| top waste by type | py 9.3 GB, dylib 8.9 GB, no-ext 7.5 GB, so 7.1 GB, jar 6.5 GB, mp4 2.3 GB, jpg 2.0 GB, mov 2.0 GB |
| where | mostly `~/.cache/uv`, `.m2`, `cdktf.out` copies; real user dups such as WhatsApp videos `x.mov` / `x(1).mov` (0.57 GB) |

Big caveat on macOS: **APFS clones are not waste.** uv, for example, clones
from its cache. Two clones share blocks, so deleting one frees nothing. Use
`getattrlist(ATTR_CMNEXT_PRIVATESIZE)`, which gives the bytes that would
actually be freed, to report *reclaimable* bytes rather than logical bytes.
Per Apple's man page this attribute exists; I haven't tested it yet. Much of
the 61 GB is likely clones or caches, so the real number will be lower.

Design, following `fclones`, the fastest of the dedup tools in published
benchmarks:

1. **Scope.** By default, exclude *managed* trees: package caches (`~/.cache`,
   `.m2`, `~/.cargo/registry`), venvs and build output. Report them as
   "cache: X GB" instead of as duplicates. That removes most of the 2.4M
   files.
2. **Pipeline:** size, then dev+inode (hardlinks), then APFS private size
   (clones), then a 4 KB prefix hash, then a suffix hash, then a full
   **BLAKE3** (tree-hashed, multithreaded, fast for large files). The
   content hash goes into `contents.blake3`, where T1 and content search
   reuse it.
3. **Incremental.** Re-hash only when (size, mtime, inode) changes. After the
   first run, duplicates are a SQL `GROUP BY content_id`.
4. **Directory duplicates.** A Merkle hash per directory (the hash of its
   sorted child names + hashes, like a git tree) finds whole copied folders,
   e.g. 30 copies of the same module. This collapses thousands of file dups
   into a few folder dups. It is the same idea as T2.
5. **Near-duplicates (later):** "Report (1).pdf" name patterns, perceptual
   hashes for images and video (czkawka does this).

Research note: Meyer & Bolosky (FAST 2011, best paper; 857 Microsoft
desktops) found that **whole-file dedup gets ~3/4 of the savings of
aggressive block-level dedup** on live file systems. That justifies
whole-file hashing here. El-Shimi et al. (USENIX ATC 2012) is the follow-up
study that drove Windows Server 2012 dedup.

**Actions** (clean / move / copy / hardlink / clone-replace) come after the
index, following Lisorto's model: propose → review → apply with a journal →
undo. "Replace duplicate with an APFS clone" (`clonefile`) frees space and
keeps both paths. It is the safest dedup action on a Mac.

---

## 5. Git relations: is branch/tag/commit stretching?

Measured on 5 real repos:

| repo | `.git/index` entries | refs (heads+tags+remotes) | naive (path, ref) rows at tips | distinct blobs at tips | distinct blobs in all history | commits | "commit touched path" rows |
|---|---:|---:|---:|---:|---:|---:|---:|
| small docs repo | 121 | 24 | 1,602 | 250 | 344 | ~69 | – |
| small infra repo | 181 | 24 | 2,573 | 528 | 3,020 | ~110 | – |
| medium app repo | 3,682 | 117 | **281,695** | 6,224 | ~9.7k | 2,002 | – |
| esp-idf | 12,809 | 143 | **807,846** | 63,505 | ~127k | 54,461 | – |
| terraform-provider-aws | 18,668 | 70 | 297,599 | 36,193 | ~296k | 94,965 | **355,174** (6 s via `git log`) |

Naive (path, ref) rows are **13–77×** the index size (terraform 16×,
medium app repo 77×). Naive history snapshots for terraform-provider-aws
would be commits × files ≈ 95k × 18.7k ≈ **1.7 billion rows**.

Deduplicated storage of the ref tips, measured. `tree_rows` counts
`(tree, name, child)` rows over the distinct trees reachable from the tips.
`blobs` counts distinct blobs at the tips.

| repo | refs | tips | distinct trees | tree_rows | rows / index | distinct blobs | blobs / index |
|---|---|---:|---:|---:|---:|---:|---:|
| small infra repo | heads+tags | 4 | 205 | 662 | 3.7× | 332 | 1.8× |
| | + remotes | 19 | 403 | 1,505 | 8.3× | 528 | 2.9× |
| medium app repo | heads+tags | 9 | 1,679 | 10,504 | 2.9× | 4,284 | 1.2× |
| | + remotes | 113 | 3,300 | 25,673 | 7.0× | 6,221 | 1.7× |
| esp-idf | heads+tags | 117 | 35,374 | 313,972 | **24.5×** | 62,090 | 4.8× |
| | + remotes | 129 | 36,440 | 327,877 | 25.6× | 63,000 | 4.9× |
| terraform-provider-aws | heads+tags | 53 | 4,509 | 131,047 | 7.0× | 34,716 | 1.9× |
| | + remotes | 67 | 4,839 | 150,514 | 8.1× | 36,193 | 1.9× |

Takeaways:
- **Tags drive the cost, not branches.** esp-idf has ~100 release tags.
- Tree dedup is 2–11× smaller than naive rows but can still reach 25× the
  index size.
- **Distinct blobs stay at 1.2–5×** the index size. That is the number to
  key on (see T2).

Tiers:

| Tier | Relation | Source | Cost | Verdict |
|---|---|---|---|---|
| **T0** | file ∈ repo; tracked / modified / ignored / untracked | `.git/index` (path, blob oid, stat) via `gix`, no `git` subprocess | = index entries (210k over all 591 repos) | **cheap, do it** |
| **T1** | content identity: git blob oid per tracked file → "same file in 3 clones / in Downloads / in a release tarball" | free for tracked files, from the index. **Caveat:** the index oid is the *staged* content, so it is valid only while the working file's stat matches the index entry. Cross-matching Downloads against repos needs the *same* hash on both sides: compute git-sha1 for non-repo files too (or lazily, only for size-matched candidates) | 1 row per file | **cheap, do it**. This is the most useful relation |
| **T2** | which branch / tag contains this file | **default:** one row per distinct `(path, blob)` at the tips, with a **Roaring bitmap of ref ids** (`roaring` crate). Q5 is a single lookup, "files in tag X" is a bitmap scan, and nothing is recursive. **Alternative:** git-style deduplicated `(tree, name, child)` rows plus a recursive walk up | bitmap variant ≈ distinct blobs = **1.2–5× the index**. Tree variant = 3–25× (measured above) | **moderate, do it.** Default refs: local branches + tags. Remotes add little except in repos with many remote branches |
| **T3** | history: which commits touched a path, file at commit X | store only deltas `(commit, path_id, change, blob_oid)`. Reconstruct "file at commit" lazily with `gix` | ~355k rows for the largest repo, but ×591 repos and slow to backfill | **stretch: opt-in per repo** (`fff git history enable <repo>`) |

Estimate for all 591 repos: 210k index entries × ~1.2–5 ≈ **0.3–1M T2
rows**. That is trivial for SQLite. Large-scale git archives work the same
way: they store content-addressed objects once and keep the relations
compact (Software Heritage, World of Code; §6).

---

## 5b. Software inventory and CVE checks

Question: should we also index applications and dependencies, e.g.
"nginx 1.x installed, Docker images", so we can check for CVEs quickly?
**Yes.** It is a natural extra relation type, and the walker already passes
every lockfile and app bundle.

The model is a local SBOM. Packages are identified by
[PURL](https://github.com/package-url/purl-spec)
(`pkg:brew/nginx@1.27.3`, `pkg:npm/lodash@4.17.21`), and by CPE where
CVE feeds need it.

| Source | How to read it | Relation |
|---|---|---|
| Homebrew | `brew info --json=v2 --installed` | package → installed (prefix path) |
| /Applications, ~/Applications | `Contents/Info.plist`: `CFBundleIdentifier`, `CFBundleShortVersionString` | app → bundle path |
| Docker / OrbStack images and containers | `docker image ls`, then an SBOM per image | image → packages inside |
| Language lockfiles in repos | `Cargo.lock`, `go.sum`, `package-lock.json` / `pnpm-lock.yaml`, `poetry.lock` / `uv.lock`, `Gemfile.lock`, `.terraform.lock.hcl` | repo (+ ref via T2) → package@version |
| Global toolchains | `pipx list`, `cargo install --list`, `npm -g ls --json`, `asdf`/`mise` | tool → path |
| Loose binaries / vendored copies | optional: hash match / SBOM scan | file → package |

**Don't write the parsers or the matcher yourself.**
- **Inventory:** shell out to `syft` (Anchore) on directories, app folders
  and images, and import its CycloneDX/SPDX JSON.
- **Matching:** download the [OSV](https://osv.dev) per-ecosystem zip dumps
  into a local table of affected version ranges, and match offline in SQL.
  Alternatively, shell out to `osv-scanner` or `grype`.
- These tool names come from general knowledge and were not re-verified
  today. Check they are still current before building.

Caveats: matching Homebrew and macOS apps to CVEs goes through CPE/NVD,
which is noisier than ecosystem PURLs (npm, crates, PyPI, Go). Expect false
positives there, and show "confidence" in the output.

Incremental: re-parse a lockfile only when its blob oid changes. With T2,
parse lockfile *blobs* once per distinct blob. That answers "is
`release-1.2` or tag `v1.2` vulnerable?" for almost nothing.

```sql
CREATE TABLE packages (id INTEGER PRIMARY KEY, purl TEXT UNIQUE,   -- with version
                       ecosystem TEXT, name TEXT, version TEXT, cpe TEXT);
CREATE TABLE package_sites (package_id INTEGER, kind TEXT,          -- installed|declared|in-image
                            file_id INTEGER, repo_id INTEGER, blob_oid BLOB, image TEXT,
                            source TEXT);                            -- brew|plist|syft|lockfile
CREATE TABLE vulns (id TEXT, ecosystem TEXT, name TEXT, introduced TEXT, fixed TEXT,
                    severity TEXT, aliases TEXT);                    -- from OSV dumps
CREATE INDEX vulns_pkg ON vulns(ecosystem, name);
```

Example commands: `fff cve nginx`, `fff cve --repo X --all-refs`,
`fff packages --installed --outdated`.

---

## 6. Storage options, judged on the queries

(Maintenance status verified 2026-11-23; crate versions in §8, papers in §9.)

| Option | Kind | Q1 names | Q2 content | Q3–Q6 relations | Q7 incremental | Simplicity | Verdict |
|---|---|---|---|---|---|---|---|
| **SQLite + FTS5** (`rusqlite`) | embedded relational + inverted index | FTS5 `trigram` tokenizer works but index ≈ several × text; scan is better | good (BM25, snippets) | **ideal**: indexes + recursive CTE | transactional upserts | one file, proven, repoidx already uses it | **system of record** |
| **Tantivy** | Lucene-like full-text (Rust) | possible | **best** at scale, fast BM25, segments | none (no joins) | segment merges, needs own doc ids | extra index dir | **upgrade path for Q2** |
| **in-memory name buffer** (`memchr` / `nucleo` / `fst`) | custom | **best**: 20–40 ms brute force; `fst` for prefix/fuzzy-automata | – | – | rebuild from SQLite | ~200 LOC | **use for Q1** |
| **redb / fjall / heed (LMDB)** | embedded KV (B-tree / LSM / B+tree mmap) | – | – | you'd hand-build every index | fast writes (fjall LSM) | low-level | only if SQLite write throughput is the bottleneck. It won't be at 4M rows |
| **DuckDB** (+ DuckPGQ) | embedded columnar OLAP, SQL/PGQ graph queries | scan fast | FTS extension basic | graph queries via SQL/PGQ | weak at many small upserts | big dependency | good for **analytics over the index** (`ATTACH` the SQLite file), not as primary store |
| **Kùzu** | embedded property-graph DB, Cypher | – | FTS ext | very good for multi-hop | ok | **archived 2025-10-10** (final 0.11.3; acquisition by Apple reported, not confirmed) | no |
| **LadybugDB** (Kùzu fork, crate `lbug` 0.22.3) | embedded graph, Cypher, FTS + vector | – | ok | very good | ok | active, but a C++ dependency and a young fork | only if relations turn truly multi-hop |
| **Grafeo** 0.6 / **HelixDB** 3.7 | Rust graph DBs (GQL/Cypher/SQL-PGQ; graph+vector) | – | – | good | ok | young (0.x) / server-first; embedded fit unverified | watch, don't depend |
| **CozoDB** / **IndraDB** | Datalog / graph, Rust | – | – | good | ok | Cozo has had no release since 2023-12; Indra low activity | no |
| **Turso** 0.8 (Rust SQLite rewrite) | SQLite-compatible, MVCC | – | FTS (on tantivy) experimental | like SQLite | concurrent writers | pre-1.0 | interesting later swap-in; not for v1 |
| **sqlite-vec / LanceDB / an HNSW library** | vector search | – | semantic search (v5) | – | – | sqlite-vec pre-1.0 and slowing; Lance very active | **later**, for embeddings |

What the papers say about our case (full refs in §9):

- **Graph engines vs RDBMS.** GRainDB (PVLDB 2022) and DuckPGQ (CIDR 2023)
  show that a relational engine extended with predefined (row-id) joins or
  SQL/PGQ handles graph workloads efficiently. That narrows the gap to native
  graph DBs; see the papers for exact factors. Kùzu (CIDR 2023) wins mainly on many-to-many
  multi-hop joins (factorisation, worst-case-optimal joins in the Leapfrog
  Triejoin line). Our joins are 1–2 hops plus one bounded tree walk, so a plain
  relational store is enough.
- **Git as a graph.** Software Heritage (MSR 2019) models all public code
  as one deduplicated Merkle DAG: content → directory → revision →
  release/branch. Boldi et al. (SANER 2020) compress that graph with WebGraph
  techniques so traversals like "which refs reach this blob" run in RAM on
  one machine. World of Code (MSR 2019, EMSE 2021) instead keeps large
  key-value maps between blob, commit, project and path. Both answer our
  Q4–Q6 at a scale of billions. Lesson: **never materialise (path, commit)
  snapshots; key on content ids and keep compact maps.** Our T2 bitmap
  variant is a small version of the WoC approach.
- **Posting lists and sets.** Roaring bitmaps (SPE 2016/2018) and Stream VByte
  (IPL 2018) are the standard compact integer sets. Use them for ref sets
  (T2) and, if needed, n-gram posting lists.
- **Name lookup.** Minimal acyclic automata (Daciuk et al. 2000), as the Rust
  `fst` crate implements, give prefix, range and Levenshtein search over
  sorted keys in little memory. Trigram indexes (Cox 2012, plocate) handle
  regex and substring. At our measured size, brute force wins on simplicity.
  Where the crossover lies is an estimate to benchmark, not a sourced number.
- **Metadata search on file systems.** Spyglass (FAST 2009) partitions the
  index hierarchically by namespace, crawls only changed files
  incrementally, and versions partitions. That validates keying everything on a directory
  tree (parent ids) and rescanning only changed subtrees.
- **SQLite itself.** "SQLite: Past, Present, and Future" (PVLDB 2022)
  describes SQLite as OLTP/B-tree first. The authors' optimisations made it
  up to 4.2× faster on the SSB analytical benchmark, and DuckDB still leads
  there. Our hot path is transactional, so SQLite fits. Heavy stats can go
  through DuckDB with `ATTACH`.
- **LSM vs B-tree KV.** O'Neil et al. (1996) designed the LSM for high
  insert rates. RocksDB's evolution (ACM ToS 2021) describes how priorities
  shifted from write amplification to space amplification and then CPU, and
  Dostoevsky (SIGMOD 2018) maps the merge-policy trade-off space. A 4M-row
  personal index rescanned incrementally is not a high-insert workload.

---

## 7. Proposed schema (SQLite)

```sql
-- namespace as a tree: 93 MB of names instead of 521 MB of paths
CREATE TABLE dirs  (id INTEGER PRIMARY KEY, parent INTEGER, name TEXT NOT NULL,
                    mtime INTEGER, repo_id INTEGER, UNIQUE(parent, name));
CREATE TABLE files (id INTEGER PRIMARY KEY, dir INTEGER NOT NULL, name TEXT NOT NULL,
                    ext TEXT, size INTEGER, mtime INTEGER, ctime INTEGER,
                    dev INTEGER, ino INTEGER, nlink INTEGER, flags INTEGER, -- SF_DATALESS etc.
                    private_size INTEGER,                                   -- APFS: bytes freed on delete
                    kind TEXT, kind_source INTEGER,                         -- ext | magic | magika
                    content_id INTEGER,                                     -- → contents
                    UNIQUE(dir, name));
CREATE INDEX files_content ON files(content_id);
CREATE INDEX files_kind ON files(kind, size);
CREATE INDEX files_ext  ON files(ext);
CREATE INDEX files_size ON files(size);                  -- dedup stage 1
CREATE TABLE dir_hash (dir INTEGER PRIMARY KEY, merkle BLOB, bytes INTEGER);
CREATE INDEX dir_hash_m ON dir_hash(merkle);             -- duplicate folders

-- content identity (T1); one row per distinct content
CREATE TABLE contents (id INTEGER PRIMARY KEY, blake3 BLOB UNIQUE, git_oid BLOB,
                       size INTEGER, text_extracted INTEGER DEFAULT 0);
CREATE INDEX contents_git ON contents(git_oid);

-- repos (T0); may ATTACH repoidx for groups, sync state, etc.
CREATE TABLE repos (id INTEGER PRIMARY KEY, root_dir INTEGER UNIQUE, git_dir TEXT,
                    head TEXT, refs_hash TEXT, index_mtime INTEGER);
CREATE TABLE git_status (file_id INTEGER PRIMARY KEY, repo_id INTEGER,
                         state INTEGER);   -- tracked, modified, untracked, ignored

-- branch/tag tips (T2): one row per distinct (path, blob) at the tips,
-- with a Roaring bitmap of ref ids. No recursion needed.
CREATE TABLE refs  (id INTEGER PRIMARY KEY, repo_id INTEGER, name TEXT,
                    kind INTEGER, commit_oid BLOB, UNIQUE(repo_id, name));
CREATE TABLE ref_files (repo_id INTEGER, path TEXT, blob_oid BLOB,
                        ref_ids BLOB,                -- serialized roaring bitmap
                        PRIMARY KEY(repo_id, path, blob_oid)) WITHOUT ROWID;
CREATE INDEX ref_files_blob ON ref_files(blob_oid);  -- Q5: blob → refs

-- history deltas (T3), opt-in per repo
CREATE TABLE commits (oid BLOB PRIMARY KEY, repo_id INTEGER, time INTEGER,
                      author TEXT) WITHOUT ROWID;
CREATE TABLE changes (commit_oid BLOB, path TEXT, change CHAR(1), blob_oid BLOB);
CREATE INDEX changes_path ON changes(path);

-- generic typed edges for everything else (duplicate-of, extracted-from,
-- sorted-into, renamed-from, user links). Keeps relations open-ended.
CREATE TABLE edges (src INTEGER, rel TEXT, dst INTEGER, meta TEXT,
                    PRIMARY KEY(src, rel, dst)) WITHOUT ROWID;
CREATE INDEX edges_rev ON edges(dst, rel);

CREATE VIRTUAL TABLE content_fts USING fts5(body, content='', tokenize='unicode61 remove_diacritics 2');
```

Q5 ("which refs contain this blob") is one index lookup on
`ref_files_blob` plus decoding a bitmap. No query in the design needs
recursion, which is the strongest argument against a graph DB.

---

## 8. Rust shape

```
walker   jwalk / ignore crate (parallel), macOS getattrlistbulk later; skip rules from repoidx
watch    notify (FSEvents) + persisted event id → Q7            (v3)
git      gix: read .git/index, refs, trees, no `git` subprocess (repoidx shells out)
types    ext table → infer/file-format (magic) → magika (lazy, unknown/mismatch only)
hash     blake3 (lazy, size+mtime guarded, staged: size→inode→clone→prefix→full); git oid from index when tracked
extract  plain text / md / code first; pdf (pdf-extract / pdfium), docx (zip+xml); OCR later
store    rusqlite (bundled, WAL, single writer thread like repoidx)
names    names.bin sidecar + memchr/rayon, nucleo for fuzzy
search   FTS5 v1 → tantivy if needed
cli      clap; `--json` everywhere (repoidx convention)
```

Crate versions (crates.io, 2026-11-23). All are actively maintained except `fst`:

| crate | version | note |
|---|---|---|
| rusqlite | 0.43.0 | bundled SQLite 3.54.1; FTS5 trigram since 3.34 |
| gix | 0.91.0 | reads index v2–v4 (threaded), refs, trees; tree-walk speed vs git not benchmarked yet |
| tantivy | 0.27.0 | upgrade path for content search |
| roaring | 0.12.0 | ref-id sets for T2 |
| redb / fjall / heed | 5.0.0 / 3.1.13 / 0.23.1 | not needed for v1 |
| duckdb | 1.20001.0 (= DuckDB 2.0.1) | optional analytics |
| fst | 0.4.7 (2021) | stable but dormant; only if prefix/fuzzy automata are needed |

---

## 9. References

Every entry below was checked against DOI / Crossref or the official page on
2026-11-23.

**Graph vs relational engines**
- Feng, Jin, Chen, Liu, Salihoğlu. *KÙZU Graph Database Management System.* CIDR 2023. cidrdb.org/cidr2023/papers/p48-jin.pdf
- ten Wolde, Singh, Szárnyas, Boncz. *DuckPGQ: Efficient Property Graph Queries in an analytical RDBMS.* CIDR 2023. ir.cwi.nl/pub/32773
- Jin, Salihoglu. *Making RDBMSs Efficient on Graph Workloads Through Predefined Joins* (GRainDB). PVLDB 15(5):1011–1023, 2022.
- Veldhuizen. *Leapfrog Triejoin: A Simple, Worst-Case Optimal Join Algorithm.* ICDT 2014. doi:10.5441/002/icdt.2014.13

**Git as a deduplicated graph**
- Pietri, Spinellis, Zacchiroli. *The Software Heritage Graph Dataset: Public Software Development Under One Roof.* MSR 2019. doi:10.1109/MSR.2019.00030
- Boldi, Pietri, Vigna, Zacchiroli. *Ultra-Large-Scale Repository Analysis via Graph Compression.* SANER 2020. doi:10.1109/SANER48275.2020.9054827
- Boldi, Vigna. *The WebGraph Framework I: Compression Techniques.* WWW 2004. doi:10.1145/988672.988752
- Ma, Bogart, Amreen, Zaretzki, Mockus. *World of Code: An Infrastructure for Mining the Universe of Open Source VCS Data.* MSR 2019. doi:10.1109/MSR.2019.00031. Extended version: EMSE 26(2), 2021, doi:10.1007/s10664-020-09905-9

**Storage engines**
- Gaffney, Prammer, Brasfield, Hipp, Kennedy, Patel. *SQLite: Past, Present, and Future.* PVLDB 15(12), 2022. doi:10.14778/3554821.3554842
- Raasveldt, Mühleisen. *DuckDB: an Embeddable Analytical Database.* SIGMOD 2019 demo. doi:10.1145/3299869.3320212
- O'Neil, Cheng, Gawlick, O'Neil. *The Log-Structured Merge-Tree.* Acta Informatica 33, 1996. doi:10.1007/s002360050048
- Dong, Kryczka, Jin, Stumm. *RocksDB: Evolution of Development Priorities in a Key-value Store Serving Large-scale Applications.* ACM ToS 17(4), 2021. doi:10.1145/3483840
- Dayan, Idreos. *Dostoevsky: Better Space-Time Trade-Offs for LSM-Tree Based Key-Value Stores via Adaptive Removal of Superfluous Merging.* SIGMOD 2018. doi:10.1145/3183713.3196927

**Posting lists, sets, name lookup**
- Chambi, Lemire, Kaser, Godin. *Better bitmap performance with Roaring bitmaps.* SP&E 46(5), 2016. doi:10.1002/spe.2325
- Lemire et al. *Roaring Bitmaps: Implementation of an Optimized Software Library.* SP&E 48(4), 2018. doi:10.1002/spe.2560
- Lemire, Kurz, Rupp. *Stream VByte: Faster Byte-Oriented Integer Compression.* IPL 130, 2018. doi:10.1016/j.ipl.2017.09.011
- Daciuk, Mihov, Watson, Watson. *Incremental Construction of Minimal Acyclic Finite-State Automata.* Computational Linguistics 26(1), 2000. doi:10.1162/089120100561601
- Gallant. *Index 1,600,000,000 Keys with Automata and Rust.* Blog, 2015. burntsushi.net/transducers/
- Cox. *Regular Expression Matching with a Trigram Index.* 2012. swtch.com/~rsc/regexp/regexp4.html
- Gunderson. *plocate* (trigram index, TurboPFor posting lists, zstd name blocks). plocate.sesse.net. No design paper; the design is in the source.

**File-system metadata search**
- Leung, Shao, Bisson, Pasupathy, Miller. *Spyglass: Fast, Scalable Metadata Search for Large-Scale Storage Systems.* USENIX FAST 2009.
- Xu, Jiang, Tian, Huang. *Propeller: A Scalable Real-Time File-Search Service in Distributed Systems.* ICDCS 2014. doi:10.1109/ICDCS.2014.46
- Hua, Jiang, Zhu, Feng, Tian. *SmartStore: A New Metadata Organization Paradigm with Semantic-Awareness.* SC '09. (DOI unverified)

**File types and deduplication**
- Google. *Magika: AI-Powered Content-Type Detection.* ICSE 2025. arXiv:2409.13768. Rust rewrite: Magika 1.0, opensource.googleblog.com/2025/11/announcing-magika-10-now-faster-smarter.html
- Meyer, Bolosky. *A Study of Practical Deduplication.* USENIX FAST 2011 (best paper). usenix.org/conference/fast11/study-practical-deduplication
- El-Shimi, Kalach, Kumar, Ottean, Li, Sengupta. *Primary Data Deduplication: Large Scale Study and System Design.* USENIX ATC 2012, pp. 285–296.
- O'Connor, Aumasson, Neves, Wilcox-O'Hearn. *BLAKE3: one function, fast everywhere.* Spec, 2020. github.com/BLAKE3-team/BLAKE3-specs
- fclones benchmarks (1.46M files: ~35 s vs jdupes ~5 min, czkawka ~2 min). Author-run; github.com/pkolaczk/fclones
- Apple `getattrlist(2)`: `ATTR_CMNEXT_PRIVATESIZE` (bytes not shared with clones or snapshots).

**Vector search (v5)**
- Malkov, Yashunin. *Efficient and Robust ANN Search Using Hierarchical Navigable Small World Graphs.* IEEE TPAMI 42(4), 2020. doi:10.1109/TPAMI.2018.2889473
- Subramanya et al. *DiskANN: Fast Accurate Billion-point Nearest Neighbor Search on a Single Node.* NeurIPS 2019.
- Pace et al. *Lance: Efficient Random Access in Columnar Storage through Adaptive Structural Encodings.* arXiv:2504.15247, 2025 (preprint).

---

## 10. Open decisions

1. **New tool vs absorbing repoidx.** Proposal: new tool now, read repoidx's db.
   Port later if it proves itself.
2. **Content scope.** Index text of documents everywhere, but *code* inside
   repos only for READMEs (ripgrep/zoekt are better for code)? Proposal: yes.
3. **T2 default refs.** Local branches + tags only, or also `refs/remotes/*`?
   Remotes double the ref count (esp-idf: 143 refs).
4. **Daemon or one-shot CLI.** One-shot plus a names sidecar is simplest;
   a daemon is needed for FSEvents and a launcher UI (v3).
5. **Spotlight as content backend** for v1 (zero extraction work) vs own
   extraction (portable, controllable).
6. **CVE scope.** Brew + apps + lockfiles first (ecosystem PURLs, good
   matching), Docker images second, loose binaries last?
7. **Name.** `findfiles` was a placeholder; the tool is now `fff` (fast find files).

## 11. v1 status (2026-11-23, measured on this Mac)

Built: `scan find big types sniff dups sql stats` (see README.md). Run over `$HOME` minus ~/Library:

| step | result |
|---|---|
| scan | 1,296,413 files indexed + 20,943 opaque dirs sized (560 GB total), 233,818 dirs, **93 s** (176 s sys: lstat-bound), 0.7 GB RSS |
| index size | index.db 253 MB, names sidecar 55 MB |
| find (name scan) | 10–40 ms for 1.5M names; kind/size filters ~20 ms |
| big / dir_stats SQL | tens of ms (precomputed subtree totals) |
| sniff | 116,510 extension-less files, 16,137 identified, 74 s (cold reads) |
| dups ≥1 MB | 904 groups, 12 GB redundant, **6.9 GB reclaimable after APFS clones**; 89 s cold, 0.3 s with the hash cache |

Space is dominated by Rust `target/` (279 GB across 16 dirs), `.cache` 47 GB, `node_modules` 14 GB.
APFS clone check verified: `cp -c` copies share CLONEID and report PRIVATESIZE 0; a plain copy gets its own id.
Next speed-up for scan: getattrlistbulk instead of readdir+lstat (sys time dominates).
