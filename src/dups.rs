//! Duplicate finder, fclones-style staged pipeline:
//!   size → (dev, ino) hardlink collapse → first+last 4 KiB BLAKE3 → full BLAKE3
//!   → APFS clone check (ATTR_CMNEXT_CLONEID / PRIVATESIZE) for real reclaimable bytes.
//! Hashes are cached in hashes.db keyed by (dev, ino, size, mtime), surviving rescans.
//! Results land in the `dup_files` table so they can be queried with `fff sql`.

use crate::fmt::{self, Render, Table};
use crate::{db, sniff::SF_DATALESS};
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const EDGE: usize = 4096;

#[derive(Clone)]
struct Inode {
    dev: i64,
    ino: i64,
    size: i64,
    mtime: i64,
    files: Vec<(i64, String)>, // (file id, path) — >1 when hardlinked
    prefix: Option<[u8; 32]>,
    full: Option<[u8; 32]>,
}

pub struct Args {
    pub min_size: String,
    pub include_caches: bool,
    pub limit: usize,
    pub threads: usize,
    /// paths printed per group (rest summarised)
    pub max_paths: usize,
}

pub fn run(a: &Args) -> Result<Table> {
    let c = db::open_index()?;
    let t0 = std::time::Instant::now();
    let min = fmt::parse_size(&a.min_size)?.max(1);
    let cache_filter = if a.include_caches {
        String::new()
    } else {
        "AND d.path NOT LIKE '%/.cache/%' AND d.path NOT LIKE '%/Caches/%' AND d.path NOT LIKE '%/cache/%'".into()
    };

    // stage 1: sizes that occur more than once
    let sql = format!(
        "WITH s AS (SELECT size FROM files WHERE size >= ?1 AND kind != 'symlink' GROUP BY size HAVING count(*) > 1)
         SELECT f.id, f.dev, f.ino, f.size, f.mtime, d.path || '/' || f.name
         FROM files f JOIN s ON s.size = f.size JOIN dirs d ON d.id = f.dir
         WHERE f.kind != 'symlink' AND (f.flags & {SF_DATALESS}) = 0 {cache_filter}"
    );
    let mut by_ino: HashMap<(i64, i64), Inode> = HashMap::new();
    {
        let mut st = c.prepare(&sql)?;
        let mut rows = st.query([min])?;
        while let Some(r) = rows.next()? {
            let (id, dev, ino, size, mtime, path): (i64, i64, i64, i64, i64, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
            by_ino
                .entry((dev, ino))
                .or_insert_with(|| Inode { dev, ino, size, mtime, files: vec![], prefix: None, full: None })
                .files
                .push((id, path));
        }
    }
    let n_files: usize = by_ino.values().map(|i| i.files.len()).sum();
    // stage 2: hardlinks collapsed; keep sizes with >1 distinct inode
    let mut by_size: HashMap<i64, Vec<Inode>> = HashMap::new();
    for i in by_ino.into_values() {
        by_size.entry(i.size).or_default().push(i);
    }
    let mut inodes: Vec<Inode> = by_size.into_values().filter(|g| g.len() > 1).flatten().collect();
    let hardlinks: usize = inodes.iter().map(|i| i.files.len() - 1).sum();
    eprintln!("stage size: {} files share a size; {} distinct inodes to hash", n_files, inodes.len());

    // cached hashes
    {
        let mut st = c.prepare("SELECT size, mtime, prefix, full FROM cache.hashes WHERE dev = ?1 AND ino = ?2")?;
        for i in inodes.iter_mut() {
            if let Ok((s, m, p, f)) = st.query_row([i.dev, i.ino], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<Vec<u8>>>(2)?, r.get::<_, Option<Vec<u8>>>(3)?))
            })
                && s == i.size && m == i.mtime {
                    i.prefix = p.and_then(|v| v.try_into().ok());
                    i.full = f.and_then(|v| v.try_into().ok());
                }
        }
    }
    let pool = rayon::ThreadPoolBuilder::new().num_threads(a.threads).build()?;

    // stage 3: first + last 4 KiB
    let t3 = std::time::Instant::now();
    pool.install(|| {
        inodes.par_iter_mut().filter(|i| i.prefix.is_none()).for_each(|i| {
            if let Some((p, full)) = edge_hash(&i.files[0].1, i.size) {
                i.prefix = Some(p);
                if full {
                    i.full = Some(p); // small file: edges cover all of it
                }
            }
        })
    });
    let mut groups: HashMap<(i64, [u8; 32]), Vec<usize>> = HashMap::new();
    for (k, i) in inodes.iter().enumerate() {
        if let Some(p) = i.prefix {
            groups.entry((i.size, p)).or_default().push(k);
        }
    }
    let need_full: Vec<usize> = groups.values().filter(|g| g.len() > 1).flatten().copied().collect();
    eprintln!("stage edges: {} inodes still candidates ({:.1}s)", need_full.len(), t3.elapsed().as_secs_f64());

    // stage 4: full hash
    let t4 = std::time::Instant::now();
    let mut todo: Vec<&mut Inode> = Vec::new();
    {
        let want: std::collections::HashSet<usize> = need_full.iter().copied().collect();
        for (k, i) in inodes.iter_mut().enumerate() {
            if want.contains(&k) && i.full.is_none() {
                todo.push(i);
            }
        }
    }
    let to_read: i64 = todo.iter().map(|i| i.size).sum();
    eprintln!("hashing {} files, {} …", todo.len(), fmt::bytes(to_read));
    pool.install(|| {
        todo.par_iter_mut().for_each(|i| {
            i.full = full_hash(&i.files[0].1, i.size);
        })
    });
    eprintln!("stage full: {:.1}s", t4.elapsed().as_secs_f64());

    // persist hash cache
    {
        let tx = c.unchecked_transaction()?;
        {
            let mut up = tx.prepare(
                "INSERT OR REPLACE INTO cache.hashes (dev, ino, size, mtime, prefix, full) VALUES (?1,?2,?3,?4,?5,?6)",
            )?;
            for i in &inodes {
                if i.prefix.is_some() {
                    up.execute(rusqlite::params![i.dev, i.ino, i.size, i.mtime, i.prefix.map(|p| p.to_vec()), i.full.map(|p| p.to_vec())])?;
                }
            }
        }
        tx.commit()?;
    }

    // final groups
    let mut fin: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    for &k in &need_full {
        if let Some(h) = inodes[k].full {
            fin.entry(h).or_default().push(k);
        }
    }
    let mut fin: Vec<([u8; 32], Vec<usize>)> = fin.into_iter().filter(|(_, g)| g.len() > 1).collect();

    // stage 5: APFS clones — copies sharing a clone id share blocks already
    struct G { hash: [u8; 32], size: i64, members: Vec<(usize, u64, i64)>, waste: i64, reclaim: i64 }
    let mut out: Vec<G> = pool.install(|| {
        fin.par_iter_mut()
            .map(|(h, g)| {
                let members: Vec<(usize, u64, i64)> = g
                    .iter()
                    .map(|&k| {
                        let (clone, private) = apfs_clone_info(&inodes[k].files[0].1).unwrap_or((0, inodes[k].size));
                        (k, clone, private)
                    })
                    .collect();
                let size = inodes[g[0]].size;
                let mut distinct: Vec<u64> = members.iter().map(|m| if m.1 == 0 { u64::MAX - m.0 as u64 } else { m.1 }).collect();
                distinct.sort();
                distinct.dedup();
                G { hash: *h, size, waste: size * (g.len() as i64 - 1), reclaim: size * (distinct.len() as i64 - 1), members }
            })
            .collect()
    });
    out.sort_by_key(|g| std::cmp::Reverse((g.reclaim, g.waste)));

    // store for SQL
    c.execute_batch(
        "DROP TABLE IF EXISTS main.dup_files;
         CREATE TABLE main.dup_files (grp INTEGER, file_id INTEGER, hash TEXT, size INTEGER, clone_id INTEGER, private_size INTEGER);",
    )?;
    {
        let tx = c.unchecked_transaction()?;
        {
            let mut ins = tx.prepare("INSERT INTO dup_files VALUES (?1,?2,?3,?4,?5,?6)")?;
            for (gi, g) in out.iter().enumerate() {
                let hex: String = g.hash[..16].iter().map(|b| format!("{b:02x}")).collect();
                for (k, clone, private) in &g.members {
                    for (fid, _) in &inodes[*k].files {
                        ins.execute(rusqlite::params![gi as i64 + 1, fid, hex, g.size, *clone as i64, private])?;
                    }
                }
            }
        }
        tx.commit()?;
    }

    let waste: i64 = out.iter().map(|g| g.waste).sum();
    let reclaim: i64 = out.iter().map(|g| g.reclaim).sum();
    let mut t = Table::new(&[("group", Render::Plain), ("size", Render::Bytes), ("copies", Render::Plain), ("reclaimable", Render::Bytes), ("path", Render::Plain)]);
    for (gi, g) in out.iter().enumerate().take(a.limit) {
        let total_names: usize = g.members.iter().map(|m| inodes[m.0].files.len()).sum();
        let mut shown = 0usize;
        for (j, (k, clone, _)) in g.members.iter().enumerate() {
            for (fi, (_, p)) in inodes[*k].files.iter().enumerate() {
                shown += 1;
                if shown > a.max_paths {
                    continue;
                }
                let note = match (fi > 0, *clone != 0 && g.members.iter().filter(|m| m.1 == *clone).count() > 1) {
                    (true, _) => " (hardlink)",
                    (_, true) => " (apfs clone)",
                    _ => "",
                };
                let first = j == 0 && fi == 0;
                t.rows.push(vec![
                    if first { (gi + 1).into() } else { serde_json::Value::Null },
                    if first { g.size.into() } else { serde_json::Value::Null },
                    if first { g.members.len().into() } else { serde_json::Value::Null },
                    if first { g.reclaim.into() } else { serde_json::Value::Null },
                    format!("{p}{note}").into(),
                ]);
            }
        }
        if total_names > a.max_paths {
            let n = serde_json::Value::Null;
            t.rows.push(vec![n.clone(), n.clone(), n.clone(), n, format!("… +{} more", total_names - a.max_paths).into()]);
        }
    }
    t.note = Some(format!(
        "{} duplicate groups; {} redundant copies ({}), reclaimable after APFS clones {}; {} hardlinked names skipped; {:.1}s total. Details: fff sql 'SELECT * FROM dup_files'",
        out.len(),
        out.iter().map(|g| g.members.len() - 1).sum::<usize>(),
        fmt::bytes(waste),
        fmt::bytes(reclaim),
        hardlinks,
        t0.elapsed().as_secs_f64()
    ));
    Ok(t)
}

/// BLAKE3 of the first and last 4 KiB (plus size). Returns (hash, covers_whole_file).
fn edge_hash(path: &str, size: i64) -> Option<([u8; 32], bool)> {
    if !crate::sniff::on_disk(path) {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut h = blake3::Hasher::new();
    let size = size as usize;
    if size <= 2 * EDGE {
        let mut buf = Vec::with_capacity(size);
        f.read_to_end(&mut buf).ok()?;
        if buf.len() != size {
            return None; // changed since scan
        }
        // same bytes as full_hash would produce for small files
        h.update(&buf);
        return Some((*h.finalize().as_bytes(), true));
    }
    let mut buf = [0u8; EDGE];
    f.read_exact(&mut buf).ok()?;
    h.update(&buf);
    f.seek(SeekFrom::End(-(EDGE as i64))).ok()?;
    f.read_exact(&mut buf).ok()?;
    h.update(&buf);
    h.update(&(size as u64).to_le_bytes());
    Some((*h.finalize().as_bytes(), false))
}

fn full_hash(path: &str, size: i64) -> Option<[u8; 32]> {
    if !crate::sniff::on_disk(path) {
        return None;
    }
    let mut h = blake3::Hasher::new();
    if size > 256 << 20 {
        h.update_mmap_rayon(path).ok()?;
    } else {
        h.update_mmap(path).ok()?;
    }
    Some(*h.finalize().as_bytes())
}

// --- APFS: getattrlist(ATTR_CMNEXT_CLONEID | ATTR_CMNEXT_PRIVATESIZE) -------------

#[repr(C)]
struct AttrList {
    bitmapcount: u16,
    reserved: u16,
    commonattr: u32,
    volattr: u32,
    dirattr: u32,
    fileattr: u32,
    forkattr: u32, // with FSOPT_ATTR_CMN_EXTENDED: ATTR_CMNEXT_* bits
}

unsafe extern "C" {
    fn getattrlist(path: *const libc::c_char, attrs: *mut AttrList, buf: *mut libc::c_void, size: libc::size_t, opts: libc::c_uint) -> libc::c_int;
}

const ATTR_BIT_MAP_COUNT: u16 = 5;
const ATTR_CMNEXT_PRIVATESIZE: u32 = 0x0000_0008;
const ATTR_CMNEXT_CLONEID: u32 = 0x0000_0100;
const FSOPT_NOFOLLOW: u32 = 0x0000_0001;
const FSOPT_ATTR_CMN_EXTENDED: u32 = 0x0000_0020;

/// (clone id, private size). Files with the same non-zero clone id share data blocks;
/// private size is what deleting this file would actually free.
pub fn apfs_clone_info(path: &str) -> Option<(u64, i64)> {
    let cpath = CString::new(path).ok()?;
    let mut al = AttrList {
        bitmapcount: ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: ATTR_CMNEXT_PRIVATESIZE | ATTR_CMNEXT_CLONEID,
    };
    let mut buf = [0u8; 64];
    let r = unsafe {
        getattrlist(cpath.as_ptr(), &mut al, buf.as_mut_ptr() as *mut _, buf.len(), FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED)
    };
    if r != 0 {
        return None;
    }
    // u32 length, then attributes in bit order: PRIVATESIZE (off_t), CLONEID (u64)
    let private = i64::from_ne_bytes(buf[4..12].try_into().ok()?);
    let clone = u64::from_ne_bytes(buf[12..20].try_into().ok()?);
    Some((clone, private))
}
