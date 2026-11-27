//! Stage 2 type detection: magic bytes (infer) for files the extension table
//! could not classify. Reads ≤ 8 KiB per file; never touches iCloud-dataless files.

use crate::{db, kinds};
use anyhow::Result;
use rayon::prelude::*;
use std::io::Read;

pub const SF_DATALESS: i64 = 0x4000_0000;

/// True when the file's bytes are on disk right now. The index's flags are from scan time; macOS can
/// evict an iCloud file since, and opening a dataless file downloads it. Check just before reading.
pub fn on_disk(path: &str) -> bool {
    use std::os::macos::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.st_flags() as i64 & SF_DATALESS == 0)
}

pub fn run(all: bool, threads: usize) -> Result<String> {
    let c = db::open_index()?;
    let t0 = std::time::Instant::now();
    let filter = if all { "f.kind = 'other'" } else { "f.ext = '' AND f.kind = 'other'" };
    let sql = format!(
        "SELECT f.id, d.path || '/' || f.name, f.ext FROM files f JOIN dirs d ON d.id = f.dir
         WHERE {filter} AND f.kind_source = 0 AND f.size > 0 AND (f.flags & {SF_DATALESS}) = 0"
    );
    let cand: Vec<(i64, String, String)> = c
        .prepare(&sql)?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    eprintln!("sniffing {} files…", cand.len());

    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
    let found: Vec<(i64, &'static str, String)> = pool.install(|| {
        cand.par_iter()
            .filter_map(|(id, path, ext)| {
                if !on_disk(path) {
                    return None;
                }
                let mut f = std::fs::File::open(path).ok()?;
                let mut buf = [0u8; 8192];
                let mut n = 0;
                while n < buf.len() {
                    match f.read(&mut buf[n..]) {
                        Ok(0) => break,
                        Ok(k) => n += k,
                        Err(_) => return None,
                    }
                }
                let t = infer::get(&buf[..n])?;
                Some((*id, kinds::from_mime(t.mime_type(), ext), t.mime_type().to_string()))
            })
            .collect()
    });

    let tx = c.unchecked_transaction()?;
    {
        let mut up = tx.prepare("UPDATE files SET kind = ?2, mime = ?3, kind_source = 1 WHERE id = ?1")?;
        let mut mark = tx.prepare("UPDATE files SET kind_source = 1 WHERE id = ?1")?;
        let hit: std::collections::HashSet<i64> = found.iter().map(|f| f.0).collect();
        for (id, kind, mime) in &found {
            up.execute(rusqlite::params![id, kind, mime])?;
        }
        // remember that we looked, so the next run skips them
        for (id, _, _) in &cand {
            if !hit.contains(id) {
                mark.execute([id])?;
            }
        }
    }
    tx.commit()?;

    let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
    for (_, k, _) in &found {
        *by.entry(k).or_default() += 1;
    }
    Ok(format!(
        "{} of {} identified by magic in {:.1}s: {:?}",
        found.len(), cand.len(), t0.elapsed().as_secs_f64(), by
    ))
}
