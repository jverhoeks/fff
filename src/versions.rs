//! Version ranges, offline and approximate. A range is a union of intervals, so we can ask both
//! "does it allow 2.1.0?" and "does it overlap 2.*?".
//!   pypi:  PEP 440 (`>=2.0,<3`, `~=2.1`, `==2.1.*`, `!=2.1.0`) plus Poetry `^` / `~`
//!   npm:   node-semver (`^2.1.0`, `~2.1`, `2.x`, `>=1 <3 || 4`, `1.2 - 2.3`; bare = exact / x-range)
//!   cargo: Cargo requirements (bare `2.1` means `^2.1`, comma = AND)
//! A user query (`fff packages -v`) uses node-semver syntax, with commas as AND, or PEP 440
//! when it contains `==`, `!=` or `~=`. None = not a version range (git URL, `file:`, `workspace:`).

use std::cmp::Ordering;

/// Release numbers, whether it is a pre-release (pre-releases sort before the release), and the
/// tag after the release (`beta.2`, `rc1`, `post1`, a Go pseudo-version's `20240101120000-abcdef`).
/// An empty tag on a pre-release is the lowest version of that release (an exclusive upper bound).
#[derive(Clone, Debug, PartialEq)]
struct V {
    rel: Vec<u64>,
    pre: bool,
    tag: String,
}

/// the lowest version of a release, below all its pre-releases
fn floor(rel: Vec<u64>) -> V {
    V { rel, pre: true, tag: String::new() }
}

/// semver-like tag order: identifiers split on . - _ and at digit/letter changes; numbers compare
/// numerically and sort before words; a tag that is a prefix of the other sorts first
fn cmp_tag(a: &str, b: &str) -> Ordering {
    fn ids(s: &str) -> Vec<&str> {
        let mut out = vec![];
        for part in s.split(['.', '-', '_']).filter(|x| !x.is_empty()) {
            let mut start = 0;
            let b = part.as_bytes();
            for i in 1..b.len() {
                if b[i].is_ascii_digit() != b[i - 1].is_ascii_digit() {
                    out.push(&part[start..i]);
                    start = i;
                }
            }
            out.push(&part[start..]);
        }
        out
    }
    let (x, y) = (ids(a), ids(b));
    for (p, q) in x.iter().zip(&y) {
        let o = match (p.parse::<u128>(), q.parse::<u128>()) {
            (Ok(m), Ok(n)) => m.cmp(&n),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            _ => p.cmp(q),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    x.len().cmp(&y.len())
}

fn cmp(a: &V, b: &V) -> Ordering {
    let n = a.rel.len().max(b.rel.len());
    for i in 0..n {
        let (x, y) = (a.rel.get(i).copied().unwrap_or(0), b.rel.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    // 2.1.0rc1 < 2.1.0 < 2.1.0.post1
    b.pre.cmp(&a.pre).then_with(|| cmp_tag(&a.tag, &b.tag))
}

/// "2.1.0", "v2.1", "2.1.0rc1", "2.1.0-beta.1", "1!2.0" (epoch dropped), "2.1.0+local"
fn parse(s: &str) -> Option<V> {
    let s = s.trim().trim_start_matches(['v', 'V', '=']);
    let s = s.rsplit_once('!').map_or(s, |(_, r)| r);
    let s = s.split('+').next()?;
    let mut rel = vec![];
    let mut rest = s;
    loop {
        let d = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if d == 0 {
            break;
        }
        rel.push(rest[..d].parse().ok()?);
        rest = &rest[d..];
        match rest.strip_prefix('.') {
            Some(r) if r.starts_with(|c: char| c.is_ascii_digit()) => rest = r,
            _ => break,
        }
    }
    if rel.is_empty() {
        return None;
    }
    // ".post1" is after the release; anything else left over (a, b, rc, dev, -beta) is before it
    let tail = rest.trim_start_matches(['.', '-', '_']).to_ascii_lowercase();
    Some(V { rel, pre: !tail.is_empty() && !tail.starts_with("post"), tag: tail })
}

/// A bound: version and whether it is inclusive.
type B = Option<(V, bool)>;

/// One interval, plus PEP 440 `!=` exclusions (point, or prefix for `!=2.1.*`).
#[derive(Clone, Debug)]
struct Iv {
    lo: B,
    hi: B,
    not: Vec<(V, bool)>,
}

const ANY: Iv = Iv { lo: None, hi: None, not: Vec::new() };

fn ge(v: V) -> Iv {
    Iv { lo: Some((v, true)), ..ANY }
}
fn lt(v: V) -> Iv {
    Iv { hi: Some((v, false)), ..ANY }
}
fn between(lo: V, hi: V) -> Iv {
    Iv { lo: Some((lo, true)), hi: Some((hi, false)), not: vec![] }
}
fn exact(v: V) -> Iv {
    Iv { lo: Some((v.clone(), true)), hi: Some((v, true)), not: vec![] }
}

fn prefix_of(p: &V, v: &V) -> bool {
    v.rel.len() >= p.rel.len() && v.rel[..p.rel.len()] == p.rel[..]
}

fn contains(iv: &Iv, v: &V) -> bool {
    iv.lo.as_ref().is_none_or(|(l, inc)| match cmp(v, l) {
        Ordering::Greater => true,
        Ordering::Equal => *inc,
        Ordering::Less => false,
    }) && iv.hi.as_ref().is_none_or(|(h, inc)| match cmp(v, h) {
        Ordering::Less => true,
        Ordering::Equal => *inc,
        Ordering::Greater => false,
    }) && !iv.not.iter().any(|(p, pre)| if *pre { prefix_of(p, v) } else { cmp(p, v) == Ordering::Equal })
}

/// Tighter of two bounds; `lower` picks the max, otherwise the min.
fn tighter(a: &B, b: &B, lower: bool) -> B {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some((x, xi)), Some((y, yi))) => Some(match (cmp(x, y), lower) {
            (Ordering::Equal, _) => (x.clone(), *xi && *yi),
            (Ordering::Greater, true) | (Ordering::Less, false) => (x.clone(), *xi),
            _ => (y.clone(), *yi),
        }),
    }
}

fn and(a: &Iv, b: &Iv) -> Iv {
    Iv { lo: tighter(&a.lo, &b.lo, true), hi: tighter(&a.hi, &b.hi, false), not: [a.not.clone(), b.not.clone()].concat() }
}

/// Non-empty? (exclusions are ignored: `!=` almost never empties a range)
fn nonempty(iv: &Iv) -> bool {
    match (&iv.lo, &iv.hi) {
        (Some((l, li)), Some((h, hi))) => match cmp(l, h) {
            Ordering::Less => true,
            Ordering::Equal => *li && *hi,
            Ordering::Greater => false,
        },
        _ => true,
    }
}

/// Partial version for semver ranges: missing or x/X/* parts are cut off.
fn partial(s: &str) -> Option<(Vec<u64>, Option<String>)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    if s.is_empty() || s == "*" || s == "x" || s == "X" {
        return Some((vec![], None));
    }
    let (core, pre) = match s.split_once('-') {
        Some((c, t)) => (c, Some(t.split('+').next().unwrap_or("").to_ascii_lowercase())),
        None => (s, None),
    };
    let core = core.split('+').next()?;
    let mut out = vec![];
    for p in core.split('.').take(3) {
        if matches!(p, "x" | "X" | "*") {
            break;
        }
        out.push(p.parse().ok()?);
    }
    Some((out, pre))
}

fn full(p: &[u64], pre: &Option<String>) -> V {
    V { rel: (0..3).map(|i| p.get(i).copied().unwrap_or(0)).collect(), pre: pre.is_some(), tag: pre.clone().unwrap_or_default() }
}

/// Upper bound: bump part `at`; excludes that version's pre-releases too (`<2.0.0` excludes 2.0.0-rc1).
fn bump(p: &[u64], at: usize) -> V {
    let mut rel: Vec<u64> = (0..=at).map(|i| p.get(i).copied().unwrap_or(0)).collect();
    rel[at] += 1;
    rel.resize(3, 0);
    floor(rel)
}

/// One semver comparator as an interval.
fn comparator(c: &str, bare_is_caret: bool) -> Option<Iv> {
    let c = c.trim();
    let (op, v) = ["^", "~>", "~", ">=", "<=", ">", "<", "="]
        .iter()
        .find_map(|op| c.strip_prefix(op).map(|r| (*op, r.trim())))
        .unwrap_or((if bare_is_caret { "^" } else { "" }, c));
    let (p, pre) = partial(v)?;
    let n = p.len();
    let lo = || full(&p, &pre);
    Some(match op {
        _ if n == 0 => ANY.clone(), // *, x
        "^" => {
            let first = p.iter().position(|x| *x != 0).unwrap_or(n - 1).min(n - 1);
            // ^0.0 → <0.1.0, ^0 → <1.0.0
            let at = if p.iter().all(|x| *x == 0) && n < 3 { n - 1 } else { first };
            between(lo(), bump(&p, at))
        }
        "~" | "~>" => between(lo(), bump(&p, if n == 1 { 0 } else { 1 })),
        "" | "=" if n < 3 => between(lo(), bump(&p, n - 1)),
        "" | "=" => exact(lo()),
        ">=" => ge(lo()),
        ">" if n < 3 => ge(bump(&p, n - 1)),
        ">" => Iv { lo: Some((lo(), false)), ..ANY },
        "<" => lt(if pre.is_some() { lo() } else { floor(lo().rel) }),
        "<=" if n < 3 => lt(bump(&p, n - 1)),
        "<=" => Iv { hi: Some((lo(), true)), ..ANY },
        _ => return None,
    })
}

fn not_a_range(r: &str) -> bool {
    r.contains(':') || r.contains('/') || r.starts_with("git") || r == "latest" || r.starts_with("link")
}

/// npm (bare = exact / x-range, space = AND) and cargo (bare = caret, comma = AND)
fn semver(range: &str, cargo: bool) -> Option<Vec<Iv>> {
    let range = range.trim();
    if not_a_range(range) {
        return None;
    }
    let mut out = vec![];
    for set in range.split("||") {
        let set = set.trim();
        let parts: Vec<&str> = if cargo { set.split(',').collect() } else { set.split_whitespace().collect() };
        // npm "1.2 - 2.3" (hyphen range)
        if !cargo && parts.len() == 3 && parts[1] == "-" {
            out.push(and(&comparator(&format!(">={}", parts[0]), false)?, &comparator(&format!("<={}", parts[2]), false)?));
            continue;
        }
        // ">= 1.2" written with a space
        let mut toks: Vec<String> = vec![];
        for p in parts {
            match toks.last_mut() {
                Some(last) if matches!(last.as_str(), ">=" | "<=" | ">" | "<" | "=" | "^" | "~") => last.push_str(p),
                _ => toks.push(p.to_string()),
            }
        }
        let mut iv = ANY.clone();
        for t in toks {
            iv = and(&iv, &comparator(&t, cargo)?);
        }
        out.push(iv);
    }
    Some(out)
}

/// PEP 440: comma-separated specifiers, all must hold.
fn pep440(range: &str) -> Option<Vec<Iv>> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(vec![ANY.clone()]);
    }
    if range.contains('@') || range.contains("://") {
        return None;
    }
    // Poetry: "a || b" is a union of PEP 440 / caret ranges
    if range.contains("||") {
        return range.split("||").map(pep440).collect::<Option<Vec<_>>>().map(|v| v.concat());
    }
    // Poetry style ("^2.1", "~2.1") also turns up in pyproject.toml
    if range.starts_with('^') || (range.starts_with('~') && !range.starts_with("~=")) {
        return semver(range, true);
    }
    let mut iv = ANY.clone();
    for spec in range.split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        let (op, s) = ["===", "==", "!=", "~=", ">=", "<=", ">", "<", "="]
            .iter()
            .find_map(|op| spec.strip_prefix(op).map(|r| (*op, r.trim())))
            .unwrap_or(("==", spec));
        let c = if let Some(prefix) = s.strip_suffix(".*") {
            let p = parse(prefix)?;
            match op {
                "==" | "=" => {
                    let mut hi = p.rel.clone();
                    *hi.last_mut()? += 1;
                    between(floor(p.rel.clone()), floor(hi))
                }
                "!=" => Iv { not: vec![(p, true)], ..ANY },
                _ => return None,
            }
        } else {
            let w = parse(s)?;
            match op {
                "==" | "===" | "=" => exact(w),
                "!=" => Iv { not: vec![(w, false)], ..ANY },
                ">=" => ge(w),
                "<=" => Iv { hi: Some((w, true)), ..ANY },
                ">" => Iv { lo: Some((w, false)), ..ANY },
                "<" => lt(if w.pre { w } else { floor(w.rel) }),
                "~=" => {
                    // ~=2.1.3 → >=2.1.3, ==2.1.*
                    if w.rel.len() < 2 {
                        return None;
                    }
                    let mut hi = w.rel[..w.rel.len() - 1].to_vec();
                    *hi.last_mut()? += 1;
                    between(w, floor(hi))
                }
                _ => return None,
            }
        };
        iv = and(&iv, &c);
    }
    Some(vec![iv])
}

/// A range as declared in ecosystem `eco`.
fn declared(eco: &str, range: &str) -> Option<Vec<Iv>> {
    match eco {
        "pypi" => pep440(range),
        "npm" => semver(range, false),
        "cargo" => semver(range, true),
        // "*": version left to a parent pom / BOM, so any version could end up there
        "maven" if range == "*" => Some(vec![ANY.clone()]),
        // maven ranges like [1.0,2.0) are rare in poms; a plain version is exact
        "maven" if !range.starts_with(['[', '(']) => Some(vec![exact(parse(range)?)]),
        _ => None,
    }
}

/// A user query: a concrete version, `2.*`, `^2.1`, `~2.1`, `>=2.1 <2.3`, `>=2.1,<2.3`,
/// `1.x || 2.x`, or PEP 440 (`~=2.1`, `==2.1.*`, `!=2.1.0`). None = not a range (use a regex).
pub struct Query(Vec<Iv>);

pub fn query(q: &str) -> Option<Query> {
    let q = q.trim();
    if q.is_empty() || not_a_range(q) {
        return None;
    }
    // one concrete version with 3+ parts is exact, tag included: 4.1.100.Final, 1.2.3.4, 2.1.0rc1
    let single = !q.contains(|c: char| c.is_whitespace() || "<>=^~*|,!".contains(c)) && !q.split('.').any(|p| matches!(p, "x" | "X"));
    if let Some(v) = parse(q).filter(|v| single && v.rel.len() >= 3) {
        return Some(Query(vec![exact(v)]));
    }
    let ivs = if q.contains("==") || q.contains("!=") || q.contains("~=") {
        pep440(q)?
    } else {
        semver(&q.replace(',', " "), false)?
    };
    Some(Query(ivs))
}

impl Query {
    /// Is a resolved (installed / pinned) version inside the query?
    pub fn matches(&self, version: &str) -> bool {
        parse(version).is_some_and(|v| self.0.iter().any(|iv| contains(iv, &v)))
    }
    /// Does a declared range overlap the query? None = the declared range is not a version range.
    pub fn overlaps(&self, eco: &str, range: &str) -> Option<bool> {
        let d = declared(eco, range)?;
        Some(self.0.iter().any(|q| d.iter().any(|r| nonempty(&and(q, r)))))
    }
    /// A single version, so "overlaps" means "allows it".
    pub fn is_point(&self) -> bool {
        matches!(&self.0[..], [Iv { lo: Some((l, true)), hi: Some((h, true)), .. }] if cmp(l, h) == Ordering::Equal)
    }
}

/// Does `range` (as declared in ecosystem `eco`) allow `version`? None = unknown.
#[cfg(test)]
pub fn allows(eco: &str, range: &str, version: &str) -> Option<bool> {
    let v = parse(version)?;
    Some(declared(eco, range)?.iter().any(|iv| contains(iv, &v)))
}

#[cfg(test)]
mod tests {
    use super::{allows, query};
    #[test]
    fn pypi() {
        let t = |r, v| allows("pypi", r, v);
        assert_eq!(t(">=2.0,<3", "2.1.0"), Some(true));
        assert_eq!(t(">=2.0,<3", "3.0.0"), Some(false));
        assert_eq!(t("~=2.1", "2.9.1"), Some(true));
        assert_eq!(t("~=2.1.0", "2.2.0"), Some(false));
        assert_eq!(t("==2.1.*", "2.1.4"), Some(true));
        assert_eq!(t("==2.1.*", "2.2.0"), Some(false));
        assert_eq!(t("!=2.1.0", "2.1.0"), Some(false));
        assert_eq!(t("", "2.1.0"), Some(true));
        assert_eq!(t("<2.1", "2.1.0rc1"), Some(false));
        assert_eq!(t("<2.1", "2.0.9"), Some(true));
        assert_eq!(t("^2.0", "2.1.0"), Some(true)); // poetry
        assert_eq!(t("^2.0", "3.0.0"), Some(false));
        assert_eq!(t("==2.1.0", "2.1"), Some(true));
        assert_eq!(t("=2.1.4", "2.1.4"), Some(true)); // poetry exact
        assert_eq!(t("@ git+https://x", "2.1.0"), None);
        assert_eq!(t(">=1.0,<1.5 || >=2.0", "2.1.0"), Some(true)); // poetry union
        assert_eq!(t(">=1.0,<1.5 || >=2.0", "1.7.0"), Some(false));
    }
    #[test]
    fn npm() {
        let t = |r, v| allows("npm", r, v);
        assert_eq!(t("^2.1.0", "2.9.0"), Some(true));
        assert_eq!(t("^2.1.0", "3.0.0"), Some(false));
        assert_eq!(t("^0.2.3", "0.3.0"), Some(false));
        assert_eq!(t("^0.0.3", "0.0.4"), Some(false));
        assert_eq!(t("~2.1.0", "2.1.9"), Some(true));
        assert_eq!(t("~2.1.0", "2.2.0"), Some(false));
        assert_eq!(t("2.x", "2.5.0"), Some(true));
        assert_eq!(t("2.1", "2.1.7"), Some(true));
        assert_eq!(t("2.1.0", "2.1.1"), Some(false));
        assert_eq!(t(">=1.0.0 <2.0.0 || ^3", "3.4.0"), Some(true));
        assert_eq!(t(">= 1.0.0 < 2.0.0", "2.0.0"), Some(false));
        assert_eq!(t("1.2 - 2.3", "2.3.9"), Some(true));
        assert_eq!(t("*", "9.9.9"), Some(true));
        assert_eq!(allows("maven", "*", "2.18.11"), Some(true));
        let q = query("4.1.100.Final").unwrap();
        assert_eq!((q.overlaps("maven", "4.1.100.Final"), q.matches("4.1.100.Final"), q.matches("4.1.100")), (Some(true), true, false));
        assert_eq!(query("1.2.3.4").unwrap().overlaps("maven", "1.2.3.4"), Some(true));
        // pre-release / post / pseudo-version tags are part of the version
        let q = |q: &str, v: &str| query(q).unwrap().matches(v);
        assert!(!q("v0.0.0-20260721132016-d427ff9ee9ad", "v0.0.0-20241212222426-2c72e554b1e7"));
        assert!(q("v0.0.0-20260721132016-d427ff9ee9ad", "0.0.0-20260721132016-d427ff9ee9ad"));
        assert!(!q("1.0.0-beta.1", "1.0.0-beta.2"));
        assert!(q("1.0.0-beta.2", "1.0.0-beta.2"));
        assert!(!q("2.1.0", "2.1.0.post1"));
        assert!(q("2.1.0", "2.1.0+local"));
        assert!(q(">=1.0.0-beta.2 <=1.0.0", "1.0.0-beta.10") && !q(">=1.0.0-beta.2 <=1.0.0", "1.0.0-beta.1"));
        assert!(!q("<2.0.0", "2.0.0-rc.1"));
        assert_eq!(t("^1.2.3", "1.2.4-beta.1"), Some(true));
        assert_eq!(allows("maven", "2.18.11", "2.18.12"), Some(false));
        assert_eq!(t("workspace:*", "1.0.0"), None);
        assert_eq!(t("github:a/b", "1.0.0"), None);
    }
    #[test]
    fn cargo() {
        let t = |r, v| allows("cargo", r, v);
        assert_eq!(t("1.2", "1.9.0"), Some(true));
        assert_eq!(t("1.2", "2.0.0"), Some(false));
        assert_eq!(t("0.10", "0.11.0"), Some(false));
        assert_eq!(t(">=1.2, <1.5", "1.4.9"), Some(true));
        assert_eq!(t("=1.2.3", "1.2.4"), Some(false));
        assert_eq!(t("~1.2", "1.2.9"), Some(true));
    }
    #[test]
    fn queries() {
        let q = |s| query(s).unwrap();
        assert!(q("2.*").matches("2.1.4") && !q("2.*").matches("3.0.0"));
        assert!(q("2.1").matches("2.1.9") && !q("2.1").matches("2.2.0"));
        assert!(q("^2.1").matches("2.9.0") && !q("^2.1").matches("2.0.9"));
        assert!(q("~2.1").matches("2.1.5") && !q("~2.1").matches("2.2.0"));
        assert!(q(">=2.1,<2.3").matches("2.2.2") && !q(">=2.1 <2.3").matches("2.3.0"));
        assert!(q("1.x || 3.x").matches("3.0.6") && !q("1.x || 3.x").matches("2.2.0"));
        assert!(q("==2.1.*").matches("2.1.0") && q("~=2.1").matches("2.4"));
        assert!(q("2.1.0").is_point() && !q("2.*").is_point());
        // declared ranges overlapping a query
        assert_eq!(q("2.*").overlaps("pypi", ">=2.1"), Some(true));
        assert_eq!(q("2.*").overlaps("pypi", ">=3.0"), Some(false));
        assert_eq!(q("2.*").overlaps("pypi", "<2.0"), Some(false));
        assert_eq!(q("2.1.0").overlaps("pypi", ">=1.5.2,<3.0.0"), Some(true));
        assert_eq!(q("2.1.0").overlaps("pypi", "^2.2"), Some(false));
        assert_eq!(q("^18").overlaps("npm", "^17.0.2 || ^18.0.0"), Some(true));
        assert_eq!(q("1.0.200").overlaps("cargo", "1.0.229"), Some(false));
        assert!(query("2\\.1\\..*").is_none()); // a regex, not a range
    }
}
