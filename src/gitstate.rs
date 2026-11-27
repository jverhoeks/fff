//! What deleting a checkout would lose, read straight from `.git` (no git binary, never written):
//! live worktrees that use this repo's history, local branches whose tip was never on a remote,
//! stashes, a detached HEAD on no branch, tracked files that differ from the git index, and an
//! unfinished merge/rebase. Used at scan time (file stats from the index db) and by the treemap's
//! Trash guard (live lstat). Untracked files are NOT checked (that needs .gitignore evaluation).
//!
//! "Unpushed" is a heuristic without reading objects: a branch tip counts as pushed when that commit
//! was ever the value of a remote-tracking ref (refs/remotes/*, packed-refs, their reflogs).
//! A branch that is behind its remote was once the remote tip, so it counts as pushed; a branch
//! created at an old commit can show up as unpushed (a false alarm, never a false "clean").

use std::collections::HashSet;
use std::os::macos::fs::MetadataExt;
use std::path::{Path, PathBuf};

const DATALESS: u32 = 0x4000_0000;

#[derive(Default, Debug)]
pub struct State {
    pub worktree: bool,           // this checkout is a linked worktree (its branches live in `main`)
    pub main: Option<String>,     // worktree: the repo that owns its history
    pub worktrees: Vec<String>,   // main repo: live linked worktrees (paths)
    pub stale_worktrees: usize,   // worktree records whose folder is gone (`git worktree prune`)
    pub branches: usize,          // local branches (main repo only)
    pub unpushed: Vec<String>,    // local branches whose tip was never on a remote (main repo only)
    pub detached_unpushed: bool,  // detached HEAD commit that is on no branch and no remote
    pub stash: usize,             // stash entries (main repo only)
    pub changed: Option<usize>,   // tracked files modified/deleted vs the index; None = not checked
    pub staged: bool,             // the index's cache tree is invalidated: `git add` since the last commit (likely staged work)
    pub op: Option<&'static str>, // merge / rebase / cherry-pick / revert / bisect in progress
    pub has_remote: bool,
    pub unknown: Vec<&'static str>, // why some checks could not run (reftable, split index, sha256 …)
}

/// A tracked file as seen on disk: (mtime ns, size), gone, or not knowable (inside an unindexed dir).
pub enum Seen {
    File(i64, u64),
    Missing,
    Skip,
}

fn read_bytes(p: &Path, cap: u64) -> Option<Vec<u8>> {
    let m = std::fs::metadata(p).ok()?;
    if m.st_flags() & DATALESS != 0 || m.len() > cap {
        return None;
    }
    std::fs::read(p).ok()
}

fn read(p: &Path) -> Option<String> {
    read_bytes(p, 64 << 20).map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn is_hash(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A linked worktree's git dir is `<common>/worktrees/<name>` with a `commondir` file; a submodule's is
/// `<super>/.git/modules/<name>` (which may itself sit under a folder called "worktrees").
pub fn is_worktree_gitdir(gitdir: &Path) -> bool {
    gitdir.parent().and_then(Path::file_name).is_some_and(|n| n == "worktrees") && gitdir.join("commondir").is_file()
}

/// The checkout's git dir and the common dir (shared by worktrees). None = not a repo.
pub fn dirs(path: &Path) -> Option<(PathBuf, PathBuf, bool)> {
    let dot = path.join(".git");
    let m = std::fs::symlink_metadata(&dot).ok()?;
    let (gitdir, linked) = if m.is_dir() {
        (dot, false)
    } else {
        let s = read(&dot)?;
        let g = s.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim().to_string();
        (path.join(g), true)
    };
    let common = match read(&gitdir.join("commondir")) {
        Some(c) => gitdir.join(c.trim()),
        None => gitdir.clone(),
    };
    let common = common.canonicalize().unwrap_or(common);
    let gitdir = gitdir.canonicalize().unwrap_or(gitdir);
    Some((gitdir, common, linked))
}

/// refs under `refs/<prefix>/` (loose files win over packed-refs): (name, hash)
fn refs(common: &Path, prefix: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    let mut seen = HashSet::new();
    let root = common.join("refs").join(prefix);
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if let Some(h) = read(&p).map(|s| s.trim().to_string()).filter(|h| is_hash(h)) {
                let name = p.strip_prefix(&root).unwrap_or(&p).to_string_lossy().into_owned();
                seen.insert(name.clone());
                out.push((name, h));
            }
        }
    }
    let want = format!("refs/{prefix}/");
    for l in read(&common.join("packed-refs")).unwrap_or_default().lines() {
        if l.starts_with('#') || l.starts_with('^') {
            continue;
        }
        if let Some((h, n)) = l.split_once(' ')
            && let Some(n) = n.strip_prefix(&want)
                && is_hash(h) && !seen.contains(n) {
                    out.push((n.to_string(), h.to_string()));
                }
    }
    out
}

/// every commit a remote-tracking ref has pointed at: current values plus reflog history
/// every commit a remote-tracking ref ever pointed at (reflogs); only read when the tips don't settle it
fn reflog_hashes(common: &Path, set: &mut HashSet<String>) {
    let mut stack = vec![common.join("logs/refs/remotes")];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(e.path());
            } else if let Some(s) = read(&e.path()) {
                for l in s.lines() {
                    let mut it = l.split(' ');
                    let (a, b) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                    for h in [a, b] {
                        if is_hash(h) && !h.bytes().all(|c| c == b'0') {
                            set.insert(h.to_string());
                        }
                    }
                }
            }
        }
    }
}

/// linked worktrees recorded in a main repo: (live paths, stale count)
fn worktrees(common: &Path) -> (Vec<String>, usize) {
    let (mut live, mut stale) = (vec![], 0);
    let Ok(rd) = std::fs::read_dir(common.join("worktrees")) else { return (live, stale) };
    for e in rd.flatten() {
        let Some(g) = read(&e.path().join("gitdir")) else { continue };
        let g = e.path().join(g.trim()); // absolute, or relative to the record
        let wt = g.parent().map(Path::to_path_buf).unwrap_or_default();
        if g.exists() {
            live.push(wt.canonicalize().unwrap_or(wt).to_string_lossy().into_owned());
        } else {
            stale += 1;
        }
    }
    live.sort();
    (live, stale)
}

pub fn read_state(path: &Path, stat: &dyn Fn(&str) -> Seen) -> Option<State> {
    let (gitdir, common, linked) = dirs(path)?;
    let mut s = State { worktree: linked && is_worktree_gitdir(&gitdir), ..Default::default() };
    let config = read(&common.join("config")).unwrap_or_default().to_ascii_lowercase();
    s.has_remote = config.contains("[remote ");
    if common.join("reftable").is_dir() || config.contains("refstorage = reftable") {
        s.unknown.push("reftable refs");
    }
    if config.contains("objectformat = sha256") {
        s.unknown.push("sha256 repo");
    }
    let local = refs(&common, "heads");
    let mut sent: HashSet<String> = refs(&common, "remotes").into_iter().map(|(_, h)| h).collect();
    let head = read(&gitdir.join("HEAD")).map(|h| h.trim().to_string()).unwrap_or_default();
    let owner = gitdir == common && !s.worktree;
    let open = (owner && local.iter().any(|(_, h)| !sent.contains(h))) || (is_hash(&head) && !sent.contains(&head));
    if open {
        reflog_hashes(&common, &mut sent); // reflogs can be MBs; most repos never need them
    }
    if s.worktree {
        s.main = common.parent().map(|p| p.to_string_lossy().into_owned());
    } else if owner {
        // branches, stash and worktrees are shared: count them on the repo that owns them
        let (live, stale) = worktrees(&common);
        s.worktrees = live;
        s.stale_worktrees = stale;
        s.branches = local.len();
        s.unpushed = local.iter().filter(|(_, h)| !sent.contains(h)).map(|(n, _)| n.clone()).collect();
        s.unpushed.sort();
        let packed_stash = || read(&common.join("packed-refs")).is_some_and(|p| p.lines().any(|l| l.ends_with(" refs/stash")));
        if common.join("refs/stash").exists() || packed_stash() {
            s.stash = read(&common.join("logs/refs/stash")).map_or(1, |l| l.lines().count().max(1));
        }
    }
    if is_hash(&head) && !sent.contains(&head) && !local.iter().any(|(_, x)| *x == head) {
        s.detached_unpushed = true;
    }
    for (f, op) in [("MERGE_HEAD", "merge"), ("rebase-merge", "rebase"), ("rebase-apply", "rebase"), ("CHERRY_PICK_HEAD", "cherry-pick"), ("REVERT_HEAD", "revert"), ("BISECT_LOG", "bisect")] {
        if gitdir.join(f).exists() {
            s.op = Some(op);
            break;
        }
    }
    if !s.unknown.contains(&"sha256 repo") {
        match changed(&gitdir, stat) {
            Ok((n, staged)) => (s.changed, s.staged) = (n, staged),
            Err(why) => s.unknown.push(why),
        }
    }
    Some(s)
}

/// Tracked files whose size or mtime differs from the git index, or that are gone (Ok(None) = no index),
/// and whether the index holds staged changes. Staging is read from the cache-tree (TREE) extension:
/// `git add` invalidates the root entry and `git commit` writes it back, so an invalid root means the
/// index differs from the last commit. Checked against `git diff --cached` on ~1,200 real repos: it caught
/// 12 of 15 staged repos and flagged 9 clean ones (errs towards a warning). No TREE extension = not known.
fn changed(gitdir: &Path, stat: &dyn Fn(&str) -> Seen) -> Result<(Option<usize>, bool), &'static str> {
    let p = gitdir.join("index");
    if !p.exists() {
        return Ok((None, false));
    }
    let b = read_bytes(&p, 1 << 30).ok_or("unreadable index")?;
    let be32 = |o: usize| -> Option<u32> { b.get(o..o + 4).map(|x| u32::from_be_bytes(x.try_into().unwrap())) };
    if b.len() < 32 || &b[..4] != b"DIRC" {
        return Err("unreadable index");
    }
    let ver = be32(4).ok_or("unreadable index")?;
    if !(2..=4).contains(&ver) {
        return Err("unknown index version");
    }
    let n = be32(8).ok_or("unreadable index")? as usize;
    let mut o = 12;
    let mut prev: Vec<u8> = vec![];
    let mut count = 0;
    for _ in 0..n {
        let e = o;
        let (msec, mnsec, mode, size) = (be32(e + 8), be32(e + 12), be32(e + 24), be32(e + 36));
        let (Some(msec), Some(mnsec), Some(mode), Some(size)) = (msec, mnsec, mode, size) else { return Err("unreadable index") };
        let flags = b.get(e + 60..e + 62).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or("unreadable index")?;
        let mut q = e + 62;
        let mut skip_wt = false;
        if ver >= 3 && flags & 0x4000 != 0 {
            let x = b.get(q..q + 2).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or("unreadable index")?;
            skip_wt = x & 0x4000 != 0;
            q += 2;
        }
        let path: Vec<u8> = if ver == 4 {
            // prefix compression: varint = bytes to drop from the previous path, then the NUL-terminated rest
            let mut c = *b.get(q).ok_or("unreadable index")? as usize;
            q += 1;
            let mut strip = c & 127;
            while c & 128 != 0 {
                c = *b.get(q).ok_or("unreadable index")? as usize;
                q += 1;
                strip = ((strip + 1) << 7) | (c & 127);
            }
            let end = q + b[q..].iter().position(|&x| x == 0).ok_or("unreadable index")?;
            let mut p = prev[..prev.len().saturating_sub(strip)].to_vec();
            p.extend_from_slice(&b[q..end]);
            o = end + 1;
            p
        } else {
            let end = q + b.get(q..).ok_or("unreadable index")?.iter().position(|&x| x == 0).ok_or("unreadable index")?;
            o = e + ((end - e + 8) & !7); // 1–8 NUL bytes pad the entry to a multiple of 8
            b[q..end].to_vec()
        };
        prev = path.clone();
        let kind = mode >> 12;
        if kind == 0o04 {
            return Err("sparse index"); // a directory entry stands for a whole skipped tree
        }
        // stage != 0: unmerged entry (conflict); gitlinks (submodules) and symlinks are not compared;
        // skip-worktree (sparse checkout) and assume-unchanged entries: git does not watch them, which is
        // exactly how local config edits get hidden, so compare them when present (absent = sparse, fine)
        if (flags >> 12) & 3 != 0 {
            count += 1;
            continue;
        }
        if kind == 0o16 || kind == 0o12 {
            continue;
        }
        let hidden = skip_wt || flags & 0x8000 != 0;
        let rel = String::from_utf8_lossy(&path);
        match stat(&rel) {
            Seen::Skip => {}
            Seen::Missing if hidden => {}
            Seen::Missing => count += 1,
            Seen::File(mtime, fsize) => {
                let same_t = if mnsec == 0 { mtime.div_euclid(1_000_000_000) == msec as i64 } else { mtime == msec as i64 * 1_000_000_000 + mnsec as i64 };
                if fsize as u32 != size || !same_t {
                    count += 1;
                }
            }
        }
    }
    // extensions: 4-byte signature + 4-byte length, until the trailing checksum
    let hash = 20;
    let mut staged = false;
    while o + 8 + hash <= b.len() {
        let sig = &b[o..o + 4];
        if sig == b"TREE" {
            // root entry: "" NUL entry_count SP subtrees LF [oid]; entry_count -1 = invalidated
            let len = be32(o + 4).unwrap_or(0) as usize;
            let d = b.get(o + 8..(o + 8 + len).min(b.len())).unwrap_or(&[]);
            staged = d.first() == Some(&0) && d.get(1) == Some(&b'-');
        }
        if sig == b"link" {
            return Err("split index");
        }
        if sig == b"sdir" {
            return Err("sparse index");
        }
        o += 8 + be32(o + 4).unwrap_or(0) as usize;
    }
    Ok((Some(count), staged))
}

/// lstat-based view of a checkout (for the live Trash check)
pub fn live_stat(root: &Path) -> impl Fn(&str) -> Seen + '_ {
    move |rel: &str| match std::fs::symlink_metadata(root.join(rel)) {
        Ok(m) => Seen::File(m.st_mtime() * 1_000_000_000 + m.st_mtime_nsec(), m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Seen::Missing,
        Err(_) => Seen::Skip,
    }
}

impl State {
    /// Things deleting this checkout would lose or break; empty = no sign of local-only work.
    pub fn risks(&self) -> Vec<String> {
        let mut r = vec![];
        let list = |v: &[String]| {
            let mut s = v.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
            if v.len() > 3 {
                s += &format!(" +{}", v.len() - 3);
            }
            s
        };
        if !self.worktrees.is_empty() {
            // where they live: worktrees often sit outside the repo (~/.t3/worktrees, tool scratch dirs)
            let home = std::env::var("HOME").unwrap_or_default();
            let mut at: Vec<(String, usize)> = vec![];
            for w in &self.worktrees {
                let d = Path::new(w).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                let d = if !home.is_empty() && d.starts_with(&home) { format!("~{}", &d[home.len()..]) } else { d };
                match at.iter_mut().find(|(x, _)| *x == d) {
                    Some((_, n)) => *n += 1,
                    None => at.push((d, 1)),
                }
            }
            at.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let mut wh = at.iter().take(2).map(|(d, n)| format!("{d} ({n})")).collect::<Vec<_>>().join(", ");
            if at.len() > 2 {
                wh += &format!(" +{} dirs", at.len() - 2);
            }
            let n = self.worktrees.len();
            r.push(format!("main repo of {n} worktree{} in {wh} (deleting it breaks them)", if n == 1 { "" } else { "s" }));
        }
        if !self.has_remote && !self.worktree {
            r.push(format!("no remote: {} branch{} exist nowhere else", self.branches, if self.branches == 1 { "" } else { "es" }));
        } else if !self.unpushed.is_empty() {
            r.push(format!("{} unpushed branch{} ({})", self.unpushed.len(), if self.unpushed.len() == 1 { "" } else { "es" }, list(&self.unpushed)));
        }
        if self.detached_unpushed {
            r.push("detached HEAD commit on no branch or remote".into());
        }
        if self.stash > 0 {
            r.push(format!("{} stash{}", self.stash, if self.stash == 1 { "" } else { "es" }));
        }
        if let Some(n) = self.changed.filter(|n| *n > 0) {
            r.push(format!("{n} tracked file{} edited or deleted", if n == 1 { "" } else { "s" }));
        }
        if self.staged {
            r.push("staged changes not committed".into());
        }
        if let Some(op) = self.op {
            r.push(format!("{op} in progress"));
        }
        r
    }

    /// One-line verdict for tables: risks, else "unknown: …", else "no sign of local work".
    pub fn verdict(&self) -> String {
        let r = self.risks();
        let mut v = if !r.is_empty() {
            r.join("; ")
        } else if !self.unknown.is_empty() {
            format!("unknown ({})", self.unknown.join(", "))
        } else if self.changed.is_none() {
            "unknown (no git index)".into()
        } else {
            "no sign of local work".into()
        };
        if !r.is_empty() && !self.unknown.is_empty() {
            v += &format!("; not checked: {}", self.unknown.join(", "));
        }
        if self.worktree {
            v += "; worktree: drop with `git worktree remove`, not the Trash";
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let o = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"]).args(args).current_dir(dir).output().unwrap();
        assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    /// builds throwaway repos in a temp dir with the git binary (tests only), then reads them back
    #[test]
    fn states() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let t = std::env::temp_dir().join(format!("ff-gitstate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let (up, a) = (t.join("up.git"), t.join("a"));
        std::fs::create_dir_all(&a).unwrap();
        git(&t, &["init", "-q", "--bare", "up.git"]);
        git(&a, &["init", "-q"]);
        std::fs::write(a.join("f.txt"), "one").unwrap();
        git(&a, &["add", "."]);
        git(&a, &["commit", "-qm", "1"]);
        git(&a, &["remote", "add", "origin", up.to_str().unwrap()]);
        git(&a, &["push", "-q", "-u", "origin", "main"]);
        let st = |p: &Path| read_state(p, &live_stat(p)).unwrap();
        let s = st(&a);
        assert_eq!(s.risks(), Vec::<String>::new(), "{s:?}");
        assert_eq!(s.verdict(), "no sign of local work");
        // edit, unpushed branch, stash, worktree
        git(&a, &["checkout", "-qb", "feat"]);
        std::fs::write(a.join("g.txt"), "two").unwrap();
        git(&a, &["add", "."]);
        git(&a, &["commit", "-qm", "2"]);
        std::fs::write(a.join("f.txt"), "edited!").unwrap();
        git(&a, &["stash", "-q"]);
        std::fs::write(a.join("f.txt"), "edited again").unwrap();
        git(&a, &["worktree", "add", "-q", t.join("wt").to_str().unwrap(), "main"]);
        let s = st(&a);
        assert_eq!(s.unpushed, ["feat"]);
        assert_eq!((s.stash, s.changed, s.worktrees.len()), (1, Some(1), 1), "{s:?}");
        let w = st(&t.join("wt"));
        assert!(w.worktree && w.risks().is_empty(), "{w:?}");
        std::fs::remove_file(t.join("wt/f.txt")).unwrap();
        assert_eq!(st(&t.join("wt")).changed, Some(1));
        // a worktree whose folder is gone is stale, not live
        std::fs::remove_dir_all(t.join("wt")).unwrap();
        let s = st(&a);
        assert_eq!((s.worktrees.len(), s.stale_worktrees), (0, 1));
        // pushing the branch clears it
        git(&a, &["push", "-q", "origin", "feat"]);
        assert!(st(&a).unpushed.is_empty());
        // a stash packed by `git gc` / `pack-refs --all` still counts
        git(&a, &["pack-refs", "--all"]);
        assert_eq!(st(&a).stash, 1);
        // staged but not committed: the index matches the disk, the cache tree is invalidated
        git(&a, &["stash", "drop", "-q"]);
        git(&a, &["checkout", "-q", "--", "."]);
        git(&a, &["commit", "-qam", "3", "--allow-empty"]);
        assert!(!st(&a).staged, "{:?}", st(&a));
        std::fs::write(a.join("g.txt"), "staged").unwrap();
        git(&a, &["add", "g.txt"]);
        let s = st(&a);
        assert!(s.staged && s.changed == Some(0), "{s:?}");
        git(&a, &["commit", "-qm", "4"]);
        // a local edit hidden with --skip-worktree is still an edit
        git(&a, &["update-index", "--skip-worktree", "f.txt"]);
        std::fs::write(a.join("f.txt"), "hidden local config edit").unwrap();
        assert_eq!(st(&a).changed, Some(1));
        let _ = std::fs::remove_dir_all(&t);
    }
}
