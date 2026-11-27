# Package inventory and incident checks

At the end of every scan, fff fills the `packages` table with every package version it can find on disk. It does this
offline and never runs a package manager. `fff packages` and `fff check` query that table.

## Three kinds of rows

| source | meaning | example |
|---|---|---|
| `installed` | the files are on disk; code from it can run | `node_modules/debug/package.json` → debug 4.4.2 |
| `lockfile` | pinned; the next `npm ci` / `uv sync` / `cargo build` installs it | `package-lock.json` → chalk 5.6.1 |
| `declared` | a range in a project file; a fresh resolve could pick any version inside it | `package.json` → debug `^4.3.0` |

For `declared` rows, `version` holds the range and `purl` is NULL. Don't compare them with SQL `=`; use
`fff packages NAME -x -v VERSION`, which evaluates the range.

## Where it looks

| ecosystem | installed | lockfile | declared |
|---|---|---|---|
| npm | `node_modules/**/package.json`, global npm under the Homebrew prefix | `package-lock.json` (v1–v3, aliases), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 and berry) | `package.json` |
| pypi | `*.dist-info`, `*.egg-info` in any venv / site-packages, global pip, `~/Library/Python` (pip --user) | `poetry.lock`, `uv.lock`, `requirements*.txt` `==` pins (including pip-compile `--generate-hashes`) | `requirements*.txt` ranges, `pyproject.toml` (PEP 621 and Poetry) |
| maven | `~/.m2` `*.pom`, Gradle module cache (`~/.gradle/caches/modules-2`) | `gradle.lockfile` | `pom.xml` (properties resolved; a version from a parent pom or BOM is `*`), `gradle/libs.versions.toml` |
| cargo | cargo registry sources, `~/.cargo/.crates2.json` (`cargo install`) | `Cargo.lock` | `Cargo.toml` |
| go | module cache (`pkg/mod/<module>@<version>`) | `go.mod` | — |
| brew | Homebrew Cellar and Caskroom, plus npm/pypi packages vendored inside kegs | — | — |

Homebrew and the global npm/pip folders are read by a packages-only pass. fff reads them without making them scan roots,
and their rows have `dir` NULL. Skip that pass with `scan --no-system`. It only runs for a default scan (no explicit roots).

**Not covered:**
- conda environments;
- `build.gradle` without a lockfile;
- Go binaries' embedded build info;
- jars inside applications;
- the `~/.npm` cache;
- `file:` / `link:` packages;
- go.mod `replace` lines.

The `check` summary lists these gaps on every run, so a clean result never claims more than it checked.

## `check`: paste the advisory

```sh
pbpaste | fff check
fff check iocs.txt
fff check 'debug@4.4.2' 'chalk@5.6.1'
fff check -e npm -u ~/src < list.txt
```

`check` reads all of these:

```text
@ctrl/tinycolor@4.1.1, 4.1.2           name@version, more versions after a comma
debug (4.4.2), chalk (5.6.1)           several packages on one line
ngx-toastr: 19.0.1                     colon
requests==2.31.0                       pip style
bar >=1.0 <1.3                         a range (one package per line)
pkg:npm/%40scope/name@1.0.1            purl
npm	left-pad	1.3.0                   an ecosystem column (CSV / TSV)
2. chalk 5.6.1                         numbered and bulleted lists
| debug | 4.4.2 |                      markdown tables
[debug](https://…) 4.4.2               markdown links
left-pad                               a bare name: any version counts
# comment                              ignored
```

It also handles em dashes, smart quotes and non-breaking spaces. Anything it can't read is reported as NOT CHECKED.

Each row is a hit:

- **INSTALLED / LOCKFILE**: a listed version is on disk or pinned. Act on these.
- **could install**: a declared range includes a listed version. Pin or bump before the next fresh install.

The summary line counts the listed packages in three groups: those that hit, those present only at other versions, and those
not present at all. It also gives the scan time and what was not covered.

## Version ranges

`packages -v` and `check` share one offline range engine, `src/versions.rs`. It models every range as a union of intervals,
which answers two questions: does this range allow version X, and do two ranges overlap.

| ecosystem | syntax |
|---|---|
| pypi | PEP 440: `>=2.0,<3`, `~=2.1`, `==2.1.*`, `!=2.1.0`; Poetry `^2.1`, `~2.1`, `a \|\| b` |
| npm | node-semver: `^2.1.0`, `~2.1`, `2.x`, `>=1 <3 \|\| 4`, `1.2 - 2.3`; a bare version is exact |
| cargo | a bare `2.1` means `^2.1`; commas mean AND |
| maven | an exact version (`4.1.100.Final`, `1.2.3.4`), or `*` when a parent pom / BOM sets it |

Prerelease, post-release and Go pseudo-version tags are compared, not dropped. Prereleases count as inside a range,
which errs towards a false positive, never a miss.

A query (`-v`) can be:
- a concrete version: exact, including any tag;
- `2.*`, `^2.1`, `~2.1`, `>=2.1 <2.3` or `>=2.1,<2.3`, `1.x || 3.x`;
- PEP 440 (`~=2.1`, `==2.1.*`, `!=2.1.0`);
- `/regex/` over the version text.

## Queries

```sh
fff packages lodash                      # every lodash version, per version
fff packages lodash --paths              # one row per location
fff packages '@babel/' -e npm -n 200     # a scope
fff packages requests -x -v '<2.32'      # pypi, exact name
fff packages log4j-core -v '>=2.0 <2.17.1'
fff packages -s installed -e brew        # Homebrew inventory
```

SQL, for anything else:

```sql
-- every resolved version of a package, and where it is
SELECT version, source, path FROM packages
WHERE name = 'pandas' AND source IN ('installed','lockfile') ORDER BY version;

-- packages installed in more than 20 versions
SELECT ecosystem, name, count(DISTINCT version) n FROM packages
WHERE source = 'installed' GROUP BY 1, 2 HAVING n > 20 ORDER BY n DESC;
```
