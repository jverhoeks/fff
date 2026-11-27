//! Brute-force name index: every file and dir name, lowercased, '\n'-joined in
//! one buffer (names.bin), with entry start offsets (offsets.bin, u32) and the
//! entry's id (ids.bin, i64; files > 0, dirs < 0). A substring query is one
//! memmem pass over the buffer — no tokenizer, no index maintenance.

use anyhow::{Context, Result};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Default)]
pub struct Builder {
    buf: Vec<u8>,
    offs: Vec<u32>,
    ids: Vec<i64>,
}

impl Builder {
    pub fn push(&mut self, name: &str, id: i64) {
        self.offs.push(self.buf.len() as u32);
        for c in name.chars().flat_map(char::to_lowercase) {
            let c = if c == '\n' { ' ' } else { c };
            let mut b = [0u8; 4];
            self.buf.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
        }
        self.buf.push(b'\n');
        self.ids.push(id);
    }

    pub fn write(&self, dir: &Path) -> Result<()> {
        let put = |name: &str, bytes: &[u8]| -> Result<()> {
            let tmp = dir.join(format!("{name}.tmp"));
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            fs::rename(&tmp, dir.join(name))?;
            Ok(())
        };
        put("names.bin", &self.buf)?;
        put("offsets.bin", as_bytes(&self.offs))?;
        put("ids.bin", as_bytes(&self.ids))?;
        Ok(())
    }
}

fn as_bytes<T: Copy>(v: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

pub struct Index {
    names: Mmap,
    offs: Mmap,
    ids: Mmap,
}

impl Index {
    pub fn open(dir: &Path) -> Result<Index> {
        let m = |n: &str| -> Result<Mmap> {
            let f = File::open(dir.join(n)).with_context(|| format!("open {n} — run `fff scan`"))?;
            Ok(unsafe { Mmap::map(&f)? })
        };
        Ok(Index { names: m("names.bin")?, offs: m("offsets.bin")?, ids: m("ids.bin")? })
    }

    fn offs(&self) -> &[u32] {
        let (a, b, c) = unsafe { self.offs.align_to::<u32>() };
        assert!(a.is_empty() && c.is_empty());
        b
    }

    fn ids(&self) -> &[i64] {
        let (a, b, c) = unsafe { self.ids.align_to::<i64>() };
        assert!(a.is_empty() && c.is_empty());
        b
    }

    /// Ids of entries whose name contains every term (case-insensitive).
    pub fn search(&self, terms: &[String]) -> Vec<i64> {
        let mut terms: Vec<Vec<u8>> = terms.iter().map(|t| t.to_lowercase().into_bytes()).collect();
        terms.retain(|t| !t.is_empty());
        if terms.is_empty() {
            return vec![];
        }
        terms.sort_by_key(|t| std::cmp::Reverse(t.len())); // longest = most selective first
        let (first, rest) = terms.split_first().unwrap();
        let buf: &[u8] = &self.names;
        let offs = self.offs();
        let ids = self.ids();

        // split into ~8 MiB chunks on entry boundaries
        const CHUNK: usize = 8 << 20;
        let mut bounds = vec![0usize];
        while *bounds.last().unwrap() < buf.len() {
            let mut e = (bounds.last().unwrap() + CHUNK).min(buf.len());
            if let Some(nl) = memchr::memchr(b'\n', &buf[e.min(buf.len())..]) {
                e += nl + 1;
            } else {
                e = buf.len();
            }
            bounds.push(e.min(buf.len()));
        }
        let finder = memchr::memmem::Finder::new(first);
        let rest: Vec<memchr::memmem::Finder> = rest.iter().map(memchr::memmem::Finder::new).collect();
        bounds
            .par_windows(2)
            .flat_map_iter(|w| {
                let (lo, hi) = (w[0], w[1]);
                let mut out = Vec::new();
                let mut last = usize::MAX;
                for pos in finder.find_iter(&buf[lo..hi]) {
                    let pos = lo + pos;
                    let i = offs.partition_point(|&o| o as usize <= pos) - 1;
                    if i == last {
                        continue;
                    }
                    last = i;
                    let start = offs[i] as usize;
                    let end = offs.get(i + 1).map(|&o| o as usize - 1).unwrap_or(buf.len() - 1);
                    let name = &buf[start..end];
                    if pos + first.len() > end {
                        continue; // spans the separator (cannot happen without '\n' in term)
                    }
                    if rest.iter().all(|f| f.find(name).is_some()) {
                        out.push(ids[i]);
                    }
                }
                out
            })
            .collect()
    }
}
