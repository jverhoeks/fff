//! Package inventory (input for CVE matching). Runs at the end of `scan`, filling `packages`:
//!   installed: node_modules/**/package.json, *.dist-info / *.egg-info, ~/.m2 *.pom, cargo registry
//!   installed: Go module cache (…/pkg/mod/<module>@<version>)
//!   installed: Gradle module cache (~/.gradle/caches/modules-2/files-2.1/<group>/<artifact>/<version>/…/*.pom)
//!   lockfile:  package-lock.json, pnpm-lock.yaml, yarn.lock (v1 + berry), Cargo.lock, poetry.lock, uv.lock, go.mod,
//!              gradle.lockfile, requirements*.txt (== pins)
//!   declared:  version ranges a project asks for (requirements*.txt, pyproject.toml, package.json,
//!              Cargo.toml outside node_modules / registries, pom.xml, gradle/libs.versions.toml);
//!              `version` holds the range, purl is NULL
//!   system:    Homebrew Cellar/Caskroom (ecosystem brew) and the pypi/npm packages vendored in kegs, global npm
//!              and pip under the Homebrew prefix, pip --user (~/Library/Python): see `system()`
//! Name/version come from the path where that is unambiguous (pypi, maven, cargo), otherwise
//! from the file. Purely local: nothing is sent anywhere.

use anyhow::Result;
use rayon::prelude::*;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct Pkg {
    pub eco: &'static str,
    pub name: String,
    pub version: String,
    /// a range from a project file, not a resolved version
    pub declared: bool,
}

/// (path, ecosystem hint, dir id, source)
type Cand = (String, String, i64, &'static str);

pub fn build(conn: &Connection, threads: usize) -> Result<(usize, usize)> {
    let mut cands: Vec<Cand> = conn
        .prepare("SELECT path, ecosystem, dir FROM manifests")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, "installed")))?
        .collect::<rusqlite::Result<_>>()?;
    // the same things outside opaque dirs (a venv not called .venv, or a --full scan)
    let more: Vec<Cand> = conn
        .prepare(
            "SELECT d.path, 'pypi', d.id, 'installed' FROM dirs d
               WHERE (d.name LIKE '%.dist-info' OR d.name LIKE '%.egg-info') AND d.opaque = 0
             UNION ALL
             SELECT d.path || '/' || f.name, 'npm', d.id, 'installed' FROM files f JOIN dirs d ON d.id = f.dir
               WHERE f.name = 'package.json' AND d.path LIKE '%/node_modules/%' AND (f.flags & 0x40000000) = 0
             UNION ALL
             SELECT d.path, 'go', d.id, 'installed' FROM dirs d
               WHERE d.name LIKE '%@v%' AND d.path LIKE '%/pkg/mod/%' AND d.path NOT LIKE '%/pkg/mod/cache/%'
             UNION ALL
             SELECT d.path || '/' || f.name, 'lock', d.id, 'lockfile' FROM files f JOIN dirs d ON d.id = f.dir
               WHERE (f.flags & 0x40000000) = 0  -- never read iCloud-evicted files (would download them)
                 AND (f.name IN ('package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'go.mod')
                      OR f.name LIKE '%gradle.lockfile'
                      OR (f.name LIKE 'requirements%.txt' AND f.size < 1000000))
                 -- go.mod of a module in the Go cache is that library's own, not a project's
                 AND NOT (f.name = 'go.mod' AND d.path LIKE '%/pkg/mod/%')
             UNION ALL
             SELECT d.path || '/' || f.name, 'decl', d.id, 'declared' FROM files f JOIN dirs d ON d.id = f.dir
               WHERE (f.flags & 0x40000000) = 0 AND f.size < 1000000
                 AND f.name IN ('pyproject.toml', 'package.json', 'Cargo.toml', 'pom.xml', 'libs.versions.toml')
                 AND d.path NOT LIKE '%/node_modules/%' AND d.path NOT LIKE '%/.cargo/registry/%'",
        )?
        .query_map([], |r| {
            let src: String = r.get(3)?;
            let src = match src.as_str() {
                "installed" => "installed",
                "declared" => "declared",
                _ => "lockfile",
            };
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, src))
        })?
        .collect::<rusqlite::Result<_>>()?;
    cands.extend(more);

    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
    let found: Vec<(usize, Vec<Pkg>)> = pool.install(|| {
        cands
            .par_iter()
            .enumerate()
            .filter_map(|(i, (path, eco, _, _))| {
                let v = parse(path, eco);
                if v.is_empty() { None } else { Some((i, v)) }
            })
            .collect()
    });

    let mut ins = conn.prepare(
        "INSERT INTO packages (ecosystem, name, version, purl, source, path, dir) VALUES (?1,?2,?3,?4,?5,?6,?7)",
    )?;
    let mut n = 0;
    for (i, pkgs) in &found {
        let (path, _, dir, source) = &cands[*i];
        let mut seen = HashSet::new();
        for p in pkgs {
            if seen.insert((p.name.as_str(), p.version.as_str())) {
                let (src, purl) = if p.declared { ("declared", None) } else { (*source, Some(purl(p))) };
                ins.execute(params![p.eco, p.name, p.version, purl, src, path, dir])?;
                n += 1;
            }
        }
    }
    Ok((n, found.len()))
}

pub fn purl(p: &Pkg) -> String {
    match p.eco {
        "npm" => format!("pkg:npm/{}@{}", p.name.replacen('@', "%40", 1), p.version),
        "maven" => {
            let (g, a) = p.name.split_once(':').unwrap_or(("", &p.name));
            format!("pkg:maven/{g}/{a}@{}", p.version)
        }
        "go" => format!("pkg:golang/{}@{}", p.name, p.version),
        // no official purl type for Homebrew
        "brew" => format!("pkg:generic/homebrew/{}@{}", p.name, p.version),
        e => format!("pkg:{e}/{}@{}", p.name, p.version),
    }
}

/// Real (non-symlink) subdirectories, hidden ones skipped: (name, path)
fn subdirs(d: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(d) else { return vec![] };
    rd.flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(n, _)| !n.starts_with('.'))
        .collect()
}

/// ~/.cargo/.crates2.json: {"installs": {"ripgrep 14.1.0 (registry+https://…crates.io-index)": {…}}}; crates.io only
fn cargo_installs(s: &str) -> Vec<Pkg> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else { return vec![] };
    let Some(m) = v.get("installs").and_then(|x| x.as_object()) else { return vec![] };
    m.keys()
        .filter_map(|k| {
            let mut it = k.splitn(3, ' ');
            let (n, ver, src) = (it.next()?, it.next()?, it.next().unwrap_or(""));
            (src.contains("crates.io-index") || src.contains("index.crates.io")).then(|| Pkg { eco: "cargo", name: n.into(), version: ver.into(), declared: false })
        })
        .collect()
}

/// Recursive read-only walk (symlinks not followed): *.dist-info / *.egg-info dirs and node_modules package.json.
/// The top levels fan out over rayon, so one huge tree (a global npm tool, a Python app keg) doesn't serialise.
fn walk_pkgs(d: &Path, depth: u32) -> Vec<(PathBuf, &'static str)> {
    let Ok(rd) = std::fs::read_dir(d) else { return vec![] };
    let mut out = vec![];
    let mut sub = vec![];
    for e in rd.flatten() {
        let Ok(t) = e.file_type() else { continue };
        let name = e.file_name();
        let name = name.to_string_lossy();
        if t.is_dir() {
            if name.ends_with(".dist-info") || name.ends_with(".egg-info") {
                out.push((e.path(), "pypi"));
            } else if depth < 40 {
                sub.push(e.path());
            }
        } else if t.is_file() && name == "package.json" && d.to_string_lossy().contains("/node_modules/") {
            out.push((e.path(), "npm"));
        }
    }
    if depth < 6 {
        out.extend(sub.par_iter().flat_map_iter(|s| walk_pkgs(s, depth + 1)).collect::<Vec<_>>());
    } else {
        for s in &sub {
            out.extend(walk_pkgs(s, depth + 1));
        }
    }
    out
}

/// Packages installed outside the scan roots, never as scan roots themselves (they must not show up in find / big /
/// treemap / Trash). Nothing is executed (no brew, npm or pip) and symlinks are not followed. Locations a scan root
/// already covers are skipped. Rows get dir = NULL: these paths have no `dirs` row.
pub fn system(conn: &Connection, threads: usize, covered: &dyn Fn(&Path) -> bool) -> Result<usize> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let mut found: Vec<(String, Pkg)> = vec![];
    let mut roots: Vec<PathBuf> = vec![];
    for prefix in ["/opt/homebrew", "/usr/local"].map(Path::new) {
        for (sub, keg) in [("Cellar", true), ("Caskroom", false)] {
            for (name, np) in subdirs(&prefix.join(sub)) {
                for (ver, vp) in subdirs(&np) {
                    // 3.12.4_1: _N is Homebrew's packaging revision, not part of the upstream version
                    let v = match ver.rsplit_once('_') {
                        Some((a, r)) if !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()) => a,
                        _ => ver.as_str(),
                    };
                    found.push((vp.to_string_lossy().into_owned(), Pkg { eco: "brew", name: name.clone(), version: v.into(), declared: false }));
                    if keg {
                        roots.push(vp); // brew-installed Python/Node tools vendor real pypi/npm packages in libexec
                    }
                }
            }
        }
        roots.push(prefix.join("lib")); // global npm (lib/node_modules), pip (lib/python3.x/site-packages); the rest are symlinks
    }
    // cargo install: ~/.cargo is opaque, so its bookkeeping file is read here
    let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".cargo"));
    let crates2 = cargo_home.join(".crates2.json");
    if let Some(s) = read_str(&crates2) {
        let path = crates2.to_string_lossy().into_owned();
        found.extend(cargo_installs(&s).into_iter().map(|p| (path.clone(), p)));
    }
    roots.push(home.join("Library/Python")); // pip install --user
    roots.push("/Library/Frameworks/Python.framework/Versions".into()); // python.org installers
    roots.retain(|r| r.is_dir() && !covered(r));
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
    let more: Vec<(String, Pkg)> = pool.install(|| {
        roots
            .par_iter()
            .flat_map(|r| walk_pkgs(r, 0))
            .flat_map_iter(|(p, eco)| {
                let path = p.to_string_lossy().into_owned();
                parse(&path, eco).into_iter().map(move |k| (path.clone(), k))
            })
            .collect()
    });
    found.extend(more);
    let mut ins = conn.prepare(
        "INSERT INTO packages (ecosystem, name, version, purl, source, path, dir) VALUES (?1,?2,?3,?4,'installed',?5,NULL)",
    )?;
    let mut seen = HashSet::new();
    for (path, p) in &found {
        if seen.insert((path.as_str(), p.name.as_str(), p.version.as_str())) {
            ins.execute(params![p.eco, p.name, p.version, purl(p), path])?;
        }
    }
    Ok(seen.len())
}

fn one(eco: &'static str, name: impl Into<String>, version: impl Into<String>) -> Vec<Pkg> {
    let (name, version) = (name.into(), version.into());
    if name.is_empty() || version.is_empty() { vec![] } else { vec![Pkg { eco, name, version, declared: false }] }
}

/// a declared range; an empty range means "any version"
fn decl(eco: &'static str, name: &str, range: &str) -> Option<Pkg> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let name = if eco == "pypi" { pep503(name) } else { name.to_string() };
    let range = range.trim();
    Some(Pkg { eco, name, version: if range.is_empty() { "*".into() } else { range.into() }, declared: true })
}

pub fn parse(path: &str, eco: &str) -> Vec<Pkg> {
    let p = Path::new(path);
    let fname = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    match eco {
        "npm" => npm_manifest(p),
        "pypi" => pypi_dir(p, &fname),
        "maven" => maven_pom(p),
        "cargo" => cargo_registry(p),
        "go" => go_modcache(p),
        _ => match fname.as_str() {
            "go.mod" => read_str(p).map(|s| go_mod(&s)).unwrap_or_default(),
            "package-lock.json" => npm_lock(p),
            "pnpm-lock.yaml" => read_str(p).map(|s| pnpm_lock(&s)).unwrap_or_default(),
            "yarn.lock" => read_str(p).map(|s| yarn_lock(&s)).unwrap_or_default(),
            "Cargo.lock" => toml_lock(p, "cargo"),
            "poetry.lock" | "uv.lock" => toml_lock(p, "pypi"),
            "pyproject.toml" => pyproject(p),
            "package.json" => npm_project(p),
            "Cargo.toml" => cargo_project(p),
            "pom.xml" => read_str(p).map(|s| pom_xml(&s)).unwrap_or_default(),
            "libs.versions.toml" => read_str(p).map(|s| gradle_catalog(&s)).unwrap_or_default(),
            f if f.ends_with("gradle.lockfile") => read_str(p).map(|s| gradle_lock(&s)).unwrap_or_default(),
            _ => requirements(p),
        },
    }
}

/// node_modules/<pkg>/package.json or node_modules/@scope/<pkg>/package.json
fn npm_manifest(p: &Path) -> Vec<Pkg> {
    let up = |n: usize| p.ancestors().nth(n).and_then(|a| a.file_name()).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
    let ok = up(2) == "node_modules" || (up(3) == "node_modules" && up(2).starts_with('@'));
    if !ok {
        return vec![];
    }
    let Ok(s) = std::fs::read(p) else { return vec![] };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&s) else { return vec![] };
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    one("npm", get("name"), get("version"))
}

/// PEP 503 normalised name
fn pep503(n: &str) -> String {
    let mut out = String::with_capacity(n.len());
    let mut dash = false;
    for c in n.chars() {
        if matches!(c, '-' | '_' | '.') {
            dash = true;
        } else {
            if dash && !out.is_empty() {
                out.push('-');
            }
            dash = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// foo_bar-1.2.3.dist-info, foo-1.2.3-py3.11.egg-info, foo.egg-info (+ PKG-INFO)
fn pypi_dir(p: &Path, fname: &str) -> Vec<Pkg> {
    let stem = fname.trim_end_matches(".dist-info").trim_end_matches(".egg-info");
    let mut it = stem.split('-');
    let name = it.next().unwrap_or("");
    if let Some(ver) = it.next() {
        return one("pypi", pep503(name), ver);
    }
    // no version in the name: read the metadata file
    for meta in ["METADATA", "PKG-INFO"] {
        if let Ok(s) = std::fs::read_to_string(p.join(meta)) {
            let field = |k: &str| s.lines().take_while(|l| !l.is_empty()).find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
            if let (Some(n), Some(v)) = (field("Name:"), field("Version:")) {
                return one("pypi", pep503(&n), v);
            }
        }
    }
    vec![]
}

/// …/repository/org/apache/foo/foo-core/1.2/foo-core-1.2.pom → org.apache.foo:foo-core@1.2
/// ~/.m2/repository/<g/r/o/u/p>/<artifact>/<version>/<artifact>-<version>.pom, or a Gradle cache
/// version dir …/modules-2/files-2.1/<group>/<artifact>/<version>
fn maven_pom(p: &Path) -> Vec<Pkg> {
    let comps: Vec<String> = p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let n = comps.len();
    if let Some(r) = comps.iter().rposition(|c| c == "files-2.1") {
        if n - r - 1 != 3 {
            return vec![];
        }
        return one("maven", format!("{}:{}", comps[r + 1], comps[r + 2]), comps[r + 3].as_str());
    }
    let (group, artifact, version) = {
        let Some(r) = comps.iter().rposition(|c| c == "repository") else { return vec![] };
        if n - r - 1 < 4 {
            return vec![];
        }
        (comps[r + 1..n - 3].join("."), &comps[n - 3], &comps[n - 2])
    };
    if !comps[n - 1].starts_with(&format!("{artifact}-{version}")) {
        return vec![];
    }
    one("maven", format!("{group}:{artifact}"), version.as_str())
}

/// gradle.lockfile (also buildscript-gradle.lockfile): `group:artifact:version=configurations`
fn gradle_lock(s: &str) -> Vec<Pkg> {
    let mut out = vec![];
    for l in s.lines().map(str::trim) {
        if l.starts_with('#') || l.starts_with("empty=") {
            continue;
        }
        let coord = l.split('=').next().unwrap_or("");
        let mut it = coord.split(':');
        if let (Some(g), Some(a), Some(v), None) = (it.next(), it.next(), it.next(), it.next()) {
            out.extend(one("maven", format!("{g}:{a}"), v));
        }
    }
    out
}

fn xml_tag<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let i = s.find(&open)? + open.len();
    let j = s[i..].find(&format!("</{tag}>"))?;
    Some(s[i..i + j].trim())
}

/// pom.xml <dependency> entries (also in dependencyManagement and plugins). `${prop}` is resolved from
/// <properties> and the project's own version; anything still unresolved (versions from a parent / BOM) is "*"
fn pom_xml(s: &str) -> Vec<Pkg> {
    let mut x = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("<!--") {
        x.push_str(&rest[..i]);
        rest = rest[i..].find("-->").map_or("", |j| &rest[i + j + 3..]);
    }
    x.push_str(rest);
    let mut props: std::collections::HashMap<String, String> = Default::default();
    if let Some(pr) = xml_tag(&x, "properties") {
        let mut r = pr;
        while let Some(i) = r.find('<') {
            let Some(j) = r[i..].find('>') else { break };
            let name = &r[i + 1..i + j];
            r = &r[i + j + 1..];
            if name.starts_with('/') || name.ends_with('/') {
                continue;
            }
            if let Some(k) = r.find(&format!("</{name}>")) {
                props.insert(name.to_string(), r[..k].trim().to_string());
                r = &r[k..];
            }
        }
    }
    // the project's own version is a direct child of <project>: before the first nested section, and
    // outside <parent>; without one, a module inherits the parent's version
    let cut = ["<dependencies>", "<dependencyManagement>", "<build>", "<properties>", "<profiles>", "<modules>", "<reporting>"]
        .iter()
        .filter_map(|t| x.find(t))
        .min()
        .unwrap_or(x.len());
    let head = &x[..cut];
    let (head, parent) = match (head.find("<parent>"), head.find("</parent>")) {
        (Some(a), Some(b)) if a < b => (format!("{}{}", &head[..a], &head[b..]), xml_tag(&head[a..b], "version")),
        _ => (head.to_string(), None),
    };
    if let Some(v) = xml_tag(&head, "version").or(parent) {
        props.insert("project.version".into(), v.to_string());
    }
    let resolve = |v: &str| -> String {
        let mut v = v.to_string();
        for _ in 0..5 {
            let Some(i) = v.find("${") else { break };
            let Some(j) = v[i..].find('}') else { break };
            match props.get(&v[i + 2..i + j]) {
                Some(r) => v = format!("{}{}{}", &v[..i], r, &v[i + j + 1..]),
                None => return String::new(),
            }
        }
        v
    };
    let mut out = vec![];
    let mut r = x.as_str();
    while let Some(i) = r.find("<dependency>") {
        let Some(j) = r[i..].find("</dependency>") else { break };
        let d = &r[i..i + j];
        r = &r[i + j..];
        if let (Some(g), Some(a)) = (xml_tag(d, "groupId"), xml_tag(d, "artifactId")) {
            let v = xml_tag(d, "version").map(resolve).unwrap_or_default();
            let (g, a) = (resolve(g), resolve(a));
            if !g.is_empty() && !a.is_empty() {
                out.extend(decl("maven", &format!("{g}:{a}"), &v));
            }
        }
    }
    out
}

/// Gradle version catalog (gradle/libs.versions.toml): [versions] plus [libraries] entries
/// `x = "g:a:1.0"`, `{ module = "g:a", version = "1.0" }`, `{ group = "g", name = "a", version.ref = "v" }`
fn gradle_catalog(s: &str) -> Vec<Pkg> {
    let q = |t: &str, key: &str| -> Option<String> {
        let mut r = t;
        while let Some(i) = r.find(key) {
            let after = r[i + key.len()..].trim_start();
            let boundary = i == 0 || !r.as_bytes()[i - 1].is_ascii_alphanumeric() && r.as_bytes()[i - 1] != b'.';
            if boundary
                && let Some(a) = after.strip_prefix('=') {
                    let a = a.trim_start().strip_prefix('"')?;
                    return a.find('"').map(|e| a[..e].to_string());
                }
            r = &r[i + key.len()..];
        }
        None
    };
    let mut versions: std::collections::HashMap<String, String> = Default::default();
    let mut libs = vec![];
    let mut sect = "";
    for l in s.lines() {
        let t = l.split(" #").next().unwrap_or("").trim();
        if t.starts_with('[') {
            sect = if t == "[versions]" { "v" } else if t == "[libraries]" { "l" } else { "" };
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if sect == "v" {
            if let Some(v) = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                versions.insert(k.to_string(), v.to_string());
            }
        } else if sect == "l" {
            libs.push(v.to_string());
        }
    }
    let mut out = vec![];
    for v in libs {
        let (coord, ver) = if let Some(s) = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            let p: Vec<&str> = s.split(':').collect();
            if p.len() < 2 {
                continue;
            }
            (format!("{}:{}", p[0], p[1]), p.get(2).map(|x| x.to_string()).unwrap_or_default())
        } else {
            let coord = match (q(&v, "module"), q(&v, "group"), q(&v, "name")) {
                (Some(m), _, _) => m,
                (_, Some(g), Some(n)) => format!("{g}:{n}"),
                _ => continue,
            };
            let ver = q(&v, "version.ref").and_then(|r| versions.get(&r).cloned()).or_else(|| q(&v, "version")).unwrap_or_default();
            (coord, ver)
        };
        out.extend(decl("maven", &coord, &ver));
    }
    out
}

/// ~/.cargo/registry/src/<index>/<name>-<semver>/Cargo.toml
fn cargo_registry(p: &Path) -> Vec<Pkg> {
    let up = |n: usize| p.ancestors().nth(n).and_then(|a| a.file_name()).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
    if up(3) != "src" || up(4) != "registry" {
        return vec![];
    }
    let d = up(1);
    // rightmost '-' followed by MAJOR.MINOR.PATCH (names like sha-1 contain '-<digit>')
    for (i, _) in d.match_indices('-').collect::<Vec<_>>().into_iter().rev() {
        let v = &d[i + 1..];
        let mut parts = v.splitn(3, '.');
        let num = |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.chars().take_while(|c| c.is_ascii_digit()).count() > 0);
        let (a, b, c) = (parts.next(), parts.next(), parts.next());
        if num(a) && a.unwrap().chars().all(|c| c.is_ascii_digit()) && num(b) && b.unwrap().chars().all(|c| c.is_ascii_digit()) && num(c) {
            return one("cargo", &d[..i], v);
        }
    }
    vec![]
}

/// package-lock.json v2/v3 ("packages") and v1 ("dependencies")
fn npm_lock(p: &Path) -> Vec<Pkg> {
    let Ok(s) = std::fs::read(p) else { return vec![] };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&s) else { return vec![] };
    let mut out = vec![];
    if let Some(pk) = v.get("packages").and_then(|x| x.as_object()) {
        for (k, e) in pk {
            let Some(i) = k.rfind("node_modules/") else { continue };
            if e.get("link").and_then(|x| x.as_bool()) == Some(true) {
                continue;
            }
            if let Some(ver) = e.get("version").and_then(|x| x.as_str()) {
                // aliases ("string-width-cjs": "npm:string-width@4") carry the real name in "name"
                let name = e.get("name").and_then(|x| x.as_str()).unwrap_or(&k[i + 13..]);
                out.extend(one("npm", name, ver));
            }
        }
    } else if let Some(d) = v.get("dependencies") {
        fn walk(d: &serde_json::Value, out: &mut Vec<Pkg>) {
            if let Some(m) = d.as_object() {
                for (name, e) in m {
                    if let Some(ver) = e.get("version").and_then(|x| x.as_str()) {
                        // an alias: "string-width-cjs": {"version": "npm:string-width@4.2.3"}
                        match ver.strip_prefix("npm:").and_then(|a| a.rsplit_once('@').filter(|(n, _)| !n.is_empty())) {
                            Some((real, v)) => out.extend(one("npm", real, v)),
                            None => out.extend(one("npm", name.as_str(), ver)),
                        }
                    }
                    if let Some(sub) = e.get("dependencies") {
                        walk(sub, out);
                    }
                }
            }
        }
        walk(d, &mut out);
    }
    out
}

/// Go module cache path escaping: an upper-case letter is stored as '!' + lower-case
fn go_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bang = false;
    for c in s.chars() {
        match (bang, c) {
            (_, '!') => bang = true,
            (true, c) => {
                out.push(c.to_ascii_uppercase());
                bang = false
            }
            (false, c) => out.push(c),
        }
    }
    out
}

/// …/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2 → github.com/BurntSushi/toml v1.3.2 (only the module root dir)
fn go_modcache(p: &Path) -> Vec<Pkg> {
    let s = p.to_string_lossy();
    let Some(i) = s.rfind("/pkg/mod/") else { return vec![] };
    let rel = &s[i + 9..];
    match rel.split_once('@') {
        Some((m, v)) if !v.contains(['/', '@']) && v.starts_with('v') => one("go", go_unescape(m), go_unescape(v)),
        _ => vec![],
    }
}

/// go.mod `require` lines. Since Go 1.17 they list every module in the build (// indirect too) at the selected
/// version, so they count as pins. go.sum is not used: it also lists versions that were only consulted.
fn go_mod(s: &str) -> Vec<Pkg> {
    let mut out = vec![];
    let mut block = false;
    for line in s.lines() {
        let l = line.split("//").next().unwrap_or("").trim();
        let req = if block {
            if l == ")" {
                block = false;
                continue;
            }
            l
        } else if let Some(r) = l.strip_prefix("require") {
            let r = r.trim();
            if r == "(" {
                block = true;
                continue;
            }
            r
        } else {
            continue;
        };
        let mut it = req.split_whitespace();
        if let (Some(m), Some(v)) = (it.next(), it.next())
            && v.starts_with('v') {
                out.extend(one("go", m.trim_matches('"'), v));
            }
    }
    out
}

fn read_str(p: &Path) -> Option<String> {
    std::fs::read(p).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// keep resolved registry versions only (not link:, file:, git URLs, workspace placeholders)
fn npm_pin(name: &str, ver: &str, out: &mut Vec<Pkg>) {
    if !name.is_empty() && ver.starts_with(|c: char| c.is_ascii_digit()) && !ver.contains("use.local") {
        out.extend(one("npm", name, ver));
    }
}

/// pnpm-lock.yaml, line-based (no YAML parser): the keys of the top-level `packages:` map.
/// v9 `'@scope/name@1.2.3':`, v6 `/name@1.2.3(peer@1.0.0):`, v5 `/@scope/name/1.2.3_peer@1.0.0:`
fn pnpm_lock(s: &str) -> Vec<Pkg> {
    let mut out = vec![];
    let mut inside = false;
    let mut v5 = false; // lockfileVersion < 6: `/name/version_peers` keys (also tried when name@version fails)
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("lockfileVersion:") {
            v5 = v.trim().trim_matches(|c| c == '\'' || c == '"').split('.').next().and_then(|m| m.parse::<u32>().ok()).is_some_and(|m| m < 6);
        }
        if !line.starts_with(' ') && !line.is_empty() {
            inside = line.trim_end() == "packages:";
            continue;
        }
        let Some(k) = line.strip_prefix("  ") else { continue };
        if !inside || k.starts_with(' ') || !k.trim_end().ends_with(':') {
            continue;
        }
        let k = k.trim_end().trim_end_matches(':').trim_matches(|c| c == '\'' || c == '"');
        let slash = k.starts_with('/');
        let k = k.strip_prefix('/').unwrap_or(k);
        let k = &k[..k.find('(').unwrap_or(k.len())];
        // v6+: name@version; v5: name = 1 segment (2 when scoped), then the version up to `_peers`
        let at = k[1.min(k.len())..].find('@').map(|i| (&k[..i + 1], &k[i + 2..]));
        let seg = k.match_indices('/').nth(if k.starts_with('@') { 1 } else { 0 }).map(|(i, _)| {
            let v = &k[i + 1..];
            (&k[..i], &v[..v.find('_').unwrap_or(v.len())])
        });
        let digit = |x: &Option<(&str, &str)>| x.is_some_and(|(_, v)| v.starts_with(|c: char| c.is_ascii_digit()));
        let pick = if v5 && digit(&seg) { seg } else if digit(&at) || !slash { at } else { seg };
        if let Some((n, v)) = pick {
            npm_pin(n, v, &mut out);
        }
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    out.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    out
}

/// package name from a yarn spec: `a@^1`, `@s/a@npm:^1`, alias `a-cjs@npm:a@^1` → `a`; None for local protocols
fn yarn_name(spec: &str) -> Option<&str> {
    // the name ends at the first @ after a possible leading scope @
    let at = |s: &str| s[1.min(s.len())..].find('@').map(|i| i + 1);
    let i = at(spec)?;
    let range = &spec[i + 1..];
    if ["workspace:", "link:", "file:", "portal:", "exec:", "patch:"].iter().any(|x| range.starts_with(x)) {
        return None;
    }
    match range.strip_prefix("npm:").and_then(|r| at(r).map(|j| &r[..j])) {
        Some(real) => Some(real),
        None => Some(&spec[..i]),
    }
}

/// yarn.lock v1 (`"a@^1", a@^2:` + `  version "1.2.3"`) and berry (`"a@npm:^1":` + `  version: 1.2.3`)
fn yarn_lock(s: &str) -> Vec<Pkg> {
    let mut out = vec![];
    let mut name: Option<String> = None;
    for line in s.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            let spec = line.trim_end().trim_end_matches(':');
            let spec = spec.split(',').next().unwrap_or("").trim().trim_matches('"');
            name = yarn_name(spec).map(str::to_string);
            continue;
        }
        let t = line.trim();
        if let (Some(n), Some(v)) = (&name, t.strip_prefix("version"))
            && v.starts_with([' ', ':']) {
                npm_pin(n, v.trim_start_matches(':').trim().trim_matches('"'), &mut out);
                name = None;
            }
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    out.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    out
}

/// [[package]] blocks with name = "…" / version = "…" (Cargo.lock, poetry.lock, uv.lock)
fn toml_lock(p: &Path, eco: &'static str) -> Vec<Pkg> {
    let Ok(s) = std::fs::read_to_string(p) else { return vec![] };
    let mut out = vec![];
    let (mut name, mut ver, mut inpkg) = (String::new(), String::new(), false);
    let flush = |name: &mut String, ver: &mut String, out: &mut Vec<Pkg>| {
        if !name.is_empty() && !ver.is_empty() {
            let n = if eco == "pypi" { pep503(name) } else { std::mem::take(name) };
            out.extend(one(eco, n, std::mem::take(ver)));
        }
        name.clear();
        ver.clear();
    };
    let val = |l: &str| l.split_once('=').map(|(_, v)| v.trim().trim_matches('"').to_string());
    for l in s.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            flush(&mut name, &mut ver, &mut out);
            inpkg = l == "[[package]]";
        } else if inpkg && (l.starts_with("name ") || l.starts_with("name=")) {
            name = val(l).unwrap_or_default();
        } else if inpkg && (l.starts_with("version ") || l.starts_with("version=")) {
            ver = val(l).unwrap_or_default();
        }
    }
    flush(&mut name, &mut ver, &mut out);
    out
}

/// PEP 508 requirement "pandas[excel] (>=2.0,<3) ; python_version>'3.8'" → (name, range)
fn pep508(s: &str) -> Option<(&str, String)> {
    let s = s.split(';').next()?.trim();
    let n = s.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))).unwrap_or(s.len());
    let (name, mut rest) = (&s[..n], s[n..].trim_start());
    if name.is_empty() {
        return None;
    }
    if rest.starts_with('[') {
        rest = rest.split_once(']').map_or("", |(_, r)| r).trim_start();
    }
    let range: String = rest.trim_matches(|c| c == '(' || c == ')').chars().filter(|c| !c.is_whitespace()).collect();
    Some((name, range))
}

/// requirements*.txt: exact pins (name==1.2.3) as resolved versions, everything else as declared ranges
fn requirements(p: &Path) -> Vec<Pkg> {
    let Ok(s) = std::fs::read_to_string(p) else { return vec![] };
    let mut out = vec![];
    // pip-compile --generate-hashes: "name==1.2.3 \\" + "--hash=…" continuation lines
    let joined = s.replace("\\\r\n", " ").replace("\\\n", " ");
    for l in joined.lines() {
        let l = l.split(" #").next().unwrap_or("").split(" --hash").next().unwrap_or("").trim();
        if l.is_empty() || l.starts_with(['#', '-']) || l.contains("://") {
            continue;
        }
        let Some((n, range)) = pep508(l) else { continue };
        match range.strip_prefix("==") {
            Some(v) if !v.contains([',', '*']) => out.extend(one("pypi", pep503(n), v)),
            _ => out.extend(decl("pypi", n, &range)),
        }
    }
    out
}

/// All quoted strings of a TOML array that starts at `from` (just after `[`), quote-aware.
fn toml_strings(src: &str) -> Vec<String> {
    let (mut out, mut cur, mut q) = (vec![], String::new(), None::<char>);
    for c in src.chars() {
        match q {
            Some(qc) if c == qc => {
                out.push(std::mem::take(&mut cur));
                q = None;
            }
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => q = Some(c),
            None if c == ']' => break,
            None => {}
        }
    }
    out
}

/// `name = "1.2"`, `name = { version = "1.2", package = "real" }`; None for workspace/path/git deps
fn toml_dep(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once('=')?;
    let k = k.trim().trim_matches('"');
    if k.contains('.') || k.is_empty() || k.starts_with('#') {
        return None; // name.workspace = true
    }
    let v = v.trim();
    if let Some(sv) = v.strip_prefix('"') {
        return Some((k.to_string(), sv.split('"').next()?.to_string()));
    }
    if v.starts_with('{') {
        let field = |f: &str| {
            let i = v.find(&format!("{f} "))
                .or_else(|| v.find(&format!("{f}=")))?;
            let r = v[i + f.len()..].trim_start().strip_prefix('=')?.trim_start().strip_prefix('"')?;
            Some(r.split('"').next()?.to_string())
        };
        let ver = field("version")?;
        return Some((field("package").unwrap_or_else(|| k.to_string()), ver));
    }
    None
}

/// pyproject.toml: PEP 621 [project] dependencies / optional-dependencies, [dependency-groups],
/// Poetry [tool.poetry.*dependencies]
fn pyproject(p: &Path) -> Vec<Pkg> {
    let Ok(s) = std::fs::read_to_string(p) else { return vec![] };
    let mut out = vec![];
    let mut sect = String::new();
    let lines: Vec<&str> = s.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with('[') && !t.contains('=') {
            sect = t.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let array_sect = sect == "project.optional-dependencies" || sect == "dependency-groups";
        let is_array = (sect == "project" && t.starts_with("dependencies")) || (array_sect && t.contains("= ["))
            || (array_sect && t.contains("=["));
        if is_array {
            if let Some(j) = t.find('[') {
                // the array may span lines: hand the rest of the file to the quote-aware reader
                let rest = std::iter::once(&t[j + 1..]).chain(lines[i + 1..].iter().copied()).collect::<Vec<_>>().join("\n");
                for r in toml_strings(&rest) {
                    if let Some((n, range)) = pep508(&r)
                        && !r.contains('@') {
                            out.extend(decl("pypi", n, &range));
                        }
                }
            }
        } else if sect.starts_with("tool.poetry") && sect.ends_with("dependencies")
            && let Some((n, range)) = toml_dep(t)
                && n != "python" {
                    out.extend(decl("pypi", &n, &range));
                }
    }
    out
}

/// a project's package.json (dependencies, devDependencies, optional, peer)
fn npm_project(p: &Path) -> Vec<Pkg> {
    let Ok(s) = std::fs::read(p) else { return vec![] };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&s) else { return vec![] };
    let mut out = vec![];
    for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        if let Some(m) = v.get(k).and_then(|x| x.as_object()) {
            for (n, r) in m {
                if let Some(r) = r.as_str() {
                    out.extend(decl("npm", n, r));
                }
            }
        }
    }
    out
}

/// a project's Cargo.toml: [dependencies], [dev-/build-dependencies], [workspace.dependencies],
/// [target.*.dependencies] and [dependencies.foo] tables
fn cargo_project(p: &Path) -> Vec<Pkg> {
    let Ok(s) = std::fs::read_to_string(p) else { return vec![] };
    let mut out = vec![];
    let mut sect = String::new();
    let mut sub: Option<(String, Option<String>)> = None; // [dependencies.foo]: name, version
    let flush = |sub: &mut Option<(String, Option<String>)>, out: &mut Vec<Pkg>| {
        if let Some((n, Some(v))) = sub.take() {
            out.extend(decl("cargo", &n, &v));
        }
    };
    let deps = |s: &str| s.ends_with("dependencies");
    for l in s.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            flush(&mut sub, &mut out);
            sect = t.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            if let Some((head, name)) = sect.rsplit_once('.')
                && deps(head) {
                    sub = Some((name.trim_matches('"').to_string(), None));
                }
            continue;
        }
        if let Some((_, v)) = sub.as_mut() {
            if let Some(r) = t.strip_prefix("version") {
                *v = r.trim_start().strip_prefix('=').map(|x| x.trim().trim_matches('"').to_string());
            }
        } else if deps(&sect)
            && let Some((n, r)) = toml_dep(t) {
                out.extend(decl("cargo", &n, &r));
            }
    }
    flush(&mut sub, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names() {
        assert_eq!(pep503("Foo__Bar.baz"), "foo-bar-baz");
        let c = cargo_registry(Path::new("/h/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sha-1-0.10.1/Cargo.toml"));
        assert_eq!((c[0].name.as_str(), c[0].version.as_str()), ("sha-1", "0.10.1"));
        let c = cargo_registry(Path::new("/h/.cargo/registry/src/x/windows_x86_64_gnu-0.52.6-rc.1/Cargo.toml"));
        assert_eq!(c[0].version, "0.52.6-rc.1");
        let m = maven_pom(Path::new("/h/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"));
        assert_eq!(purl(&m[0]), "pkg:maven/org.apache.commons/commons-lang3@3.12.0");
        let p = pypi_dir(Path::new("/x/typing_extensions-4.12.2.dist-info"), "typing_extensions-4.12.2.dist-info");
        assert_eq!(purl(&p[0]), "pkg:pypi/typing-extensions@4.12.2");
        assert_eq!(purl(&Pkg { eco: "npm", name: "@babel/core".into(), version: "7.0.0".into(), declared: false }), "pkg:npm/%40babel/core@7.0.0");
        assert_eq!(pep508("Pandas[excel] (>= 2.0, <3) ; python_version>'3.8'"), Some(("Pandas", ">=2.0,<3".to_string())));
        assert_eq!(toml_dep(r#"serde = { version = "1.0", features = ["derive"] }"#), Some(("serde".into(), "1.0".into())));
        assert_eq!(toml_dep(r#"foo = { workspace = true }"#), None);
    }

    #[test]
    fn java() {
        let m = maven_pom(Path::new("/h/.gradle/caches/modules-2/files-2.1/io.smallrye/jandex/3.5.2"));
        assert_eq!(purl(&m[0]), "pkg:maven/io.smallrye/jandex@3.5.2");
        assert!(maven_pom(Path::new("/h/.gradle/caches/modules-2/files-2.1/io.smallrye/jandex/3.5.2/ea32/jandex-3.5.2.pom")).is_empty());
        let l = gradle_lock("# comment\ncom.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n");
        assert_eq!(nv(l), ["com.google.guava:guava@32.1.2-jre"]);
        let pom = r#"<project><parent><groupId>p</groupId><artifactId>par</artifactId><version>9.9</version></parent>
          <version>1.0-SNAPSHOT</version><properties><jackson.version>2.15.2</jackson.version></properties>
          <!-- <dependency><groupId>x</groupId><artifactId>gone</artifactId><version>1</version></dependency> -->
          <dependencies>
            <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
            <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
            <dependency><groupId>me</groupId><artifactId>sib</artifactId><version>${project.version}</version></dependency>
            <dependency><groupId>u</groupId><artifactId>unres</artifactId><version>${nope}</version></dependency>
          </dependencies></project>"#;
        assert_eq!(nv(pom_xml(pom)), [
            "com.fasterxml.jackson.core:jackson-databind@2.15.2", "org.slf4j:slf4j-api@*", "me:sib@1.0-SNAPSHOT", "u:unres@*"]);
        let module = r#"<project><parent><groupId>p</groupId><artifactId>par</artifactId><version>9.9</version></parent>
          <build><plugins><plugin><artifactId>x</artifactId><version>3.1</version></plugin></plugins></build>
          <dependencies><dependency><groupId>me</groupId><artifactId>sib</artifactId><version>${project.version}</version></dependency></dependencies></project>"#;
        assert_eq!(nv(pom_xml(module)), ["me:sib@9.9"]);
        let cat = "[versions]\nslf4j = \"2.0.17\" # pin\n[libraries]\na = { module = \"org.slf4j:slf4j-api\", version.ref = \"slf4j\" }\n\
                   b = { group = \"com.x\", name = \"y\", version = \"1.2\" }\nc = \"g:h:3.0\"\nd = { module = \"g:noversion\" }\n[plugins]\nq = { id = \"z\", version = \"1\" }\n";
        assert_eq!(nv(gradle_catalog(cat)), ["org.slf4j:slf4j-api@2.0.17", "com.x:y@1.2", "g:h@3.0", "g:noversion@*"]);
    }

    fn nv(v: Vec<Pkg>) -> Vec<String> {
        v.into_iter().map(|p| format!("{}@{}", p.name, p.version)).collect()
    }

    /// cargo test --release -- --ignored --nocapture system_pass
    #[test]
    #[ignore]
    fn system_pass() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        let t = std::time::Instant::now();
        let n = system(&c, crate::default_threads(2), &|_| false).unwrap();
        eprintln!("{n} system packages in {:.2}s", t.elapsed().as_secs_f64());
    }

    #[test]
    fn cargo_install() {
        let s = r#"{"installs": {"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {},
            "mytool 0.1.0 (path+file:///Users/x/src/mytool)": {}, "sparse 1.2.3 (sparse+https://index.crates.io/)": {}}}"#;
        assert_eq!(nv(cargo_installs(s)), ["ripgrep@14.1.0", "sparse@1.2.3"]);
    }

    #[test]
    fn go() {
        let m = "module example.com/app\n\ngo 1.22\n\nrequire github.com/spf13/cobra v1.8.0\n\nrequire (\n\tgithub.com/BurntSushi/toml v1.3.2 // indirect\n\tgolang.org/x/sys v0.20.0\n)\n\nreplace golang.org/x/sys => ../sys\n";
        assert_eq!(nv(go_mod(m)), ["github.com/spf13/cobra@v1.8.0", "github.com/BurntSushi/toml@v1.3.2", "golang.org/x/sys@v0.20.0"]);
        assert_eq!(nv(go_modcache(Path::new("/h/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2"))), ["github.com/BurntSushi/toml@v1.3.2"]);
        assert!(go_modcache(Path::new("/h/go/pkg/mod/github.com/x/y@v1.0.0/internal/z@v2")).is_empty());
        assert_eq!(purl(&go_modcache(Path::new("/h/go/pkg/mod/golang.org/x/sys@v0.20.0"))[0]), "pkg:golang/golang.org/x/sys@v0.20.0");
    }

    #[test]
    fn pnpm() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      vite:\n        specifier: ^6.0.0\n        version: 6.1.0\n\npackages:\n\n  '@adobe/css-tools@4.5.0':\n    resolution: {integrity: sha512-x}\n\n  debug@4.4.1:\n    resolution: {integrity: sha512-y}\n    peerDependencies:\n      supports-color: '*'\n\n  local-thing@link:../x:\n    resolution: {directory: ../x}\n\n  vendored@file:packages/3rdparty:\n    resolution: {directory: packages/3rdparty}\n\nsnapshots:\n\n  debug@4.4.1(supports-color@8.1.1):\n    dependencies:\n      ms: 2.1.3\n";
        assert_eq!(nv(pnpm_lock(v9)), ["@adobe/css-tools@4.5.0", "debug@4.4.1"]);
        let v6 = "lockfileVersion: '6.0'\npackages:\n  /@babel/core@7.24.0:\n    resolution: {}\n  /react-dom@18.2.0(react@18.2.0):\n    dependencies:\n      react: 18.2.0\n";
        assert_eq!(nv(pnpm_lock(v6)), ["@babel/core@7.24.0", "react-dom@18.2.0"]);
        let v5 = "lockfileVersion: 5.4\npackages:\n  /@babel/core/7.24.0:\n    resolution: {}\n  /react-dom/18.2.0_react@18.2.0:\n    dev: false\n  /@a_b/c_d/1.0.0_@types+react@18.0.0:\n    dev: true\n";
        assert_eq!(nv(pnpm_lock(v5)), ["@a_b/c_d@1.0.0", "@babel/core@7.24.0", "react-dom@18.2.0"]);
    }

    #[test]
    fn yarn() {
        let v1 = "# yarn lockfile v1\n\n\n\"@ampproject/remapping@^2.2.0\":\n  version \"2.3.0\"\n  dependencies:\n    \"@jridgewell/gen-mapping\" \"^0.3.5\"\n\ntslib@^2.1.0, tslib@^2.6.2:\n  version \"2.8.1\"\n\n\"strip-ansi-cjs@npm:strip-ansi@^6.0.1\":\n  version \"6.0.1\"\n";
        assert_eq!(nv(yarn_lock(v1)), ["@ampproject/remapping@2.3.0", "strip-ansi@6.0.1", "tslib@2.8.1"]);
        let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"@babel/core@npm:^7.0.0, @babel/core@npm:^7.24.0\":\n  version: 7.24.0\n  resolution: \"@babel/core@npm:7.24.0\"\n\n\"my-app@workspace:.\":\n  version: 0.0.0-use.local\n\n\"resolve@patch:resolve@npm%3A^1.22.0#~builtin<compat/resolve>\":\n  version: 1.22.8\n\n\"resolve@npm:^1.22.0\":\n  version: 1.22.8\n\n\"react-loadable@npm:@docusaurus/react-loadable@5.5.2\":\n  version: 5.5.2\n";
        assert_eq!(nv(yarn_lock(berry)), ["@babel/core@7.24.0", "@docusaurus/react-loadable@5.5.2", "resolve@1.22.8"]);
        let lock = r#"{"packages": {"": {"name": "app"}, "node_modules/strip-ansi-cjs": {"name": "strip-ansi", "version": "6.0.1"},
            "node_modules/debug": {"version": "4.4.1"}, "node_modules/x": {"link": true, "version": "1.0.0"}}}"#;
        let tmp = std::env::temp_dir().join(format!("ff-npm-lock-{}.json", std::process::id()));
        std::fs::write(&tmp, lock).unwrap();
        let mut got = nv(npm_lock(&tmp));
        got.sort();
        std::fs::remove_file(&tmp).ok();
        assert_eq!(got, ["debug@4.4.1", "strip-ansi@6.0.1"]);
    }
}
