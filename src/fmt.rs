//! Output helpers: sizes, dates, aligned tables, JSON.

use serde_json::{Map, Value};

pub fn bytes(n: i64) -> String {
    const U: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = n as f64;
    let mut i = 0;
    while v.abs() >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n}B") } else if v < 10.0 { format!("{v:.1}{}", U[i]) } else { format!("{v:.0}{}", U[i]) }
}

/// Parse "10M", "1.5G", "500k", "123".
pub fn parse_size(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&s[..s.len() - 1], 1i64 << 10),
        Some('m') => (&s[..s.len() - 1], 1 << 20),
        Some('g') => (&s[..s.len() - 1], 1 << 30),
        Some('t') => (&s[..s.len() - 1], 1 << 40),
        Some('b') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    Ok((num.parse::<f64>()? * mult as f64) as i64)
}

/// ns since epoch → local "YYYY-MM-DD HH:MM".
pub fn date(ns: i64) -> String {
    let t: libc::time_t = (ns / 1_000_000_000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!("{:04}-{:02}-{:02} {:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
}

/// Rows of JSON values; printed as an aligned table or as a JSON array.
pub struct Table {
    pub cols: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// how to render a column in text mode
    pub render: Vec<Render>,
    /// one-line summary (stderr in text mode, `note` field in JSON)
    pub note: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Render {
    Plain,
    Bytes,
    Date,
    Pct,
}

impl Table {
    pub fn new(cols: &[(&str, Render)]) -> Table {
        Table {
            cols: cols.iter().map(|c| c.0.to_string()).collect(),
            render: cols.iter().map(|c| c.1).collect(),
            rows: vec![],
            note: None,
        }
    }

    /// Array of row objects. `human`: dates as text, and a `<col>_human` twin for byte columns
    /// (what an LLM reads best); otherwise raw numbers (what scripts want).
    pub fn to_json(&self, human: bool) -> Value {
        Value::Array(self.rows.iter().map(|r| {
            let mut m = Map::new();
            for ((c, v), how) in self.cols.iter().zip(r).zip(&self.render) {
                match (human, how, v) {
                    (true, Render::Date, Value::Number(_)) => { m.insert(c.clone(), cell(v, *how).into()); }
                    (true, Render::Bytes, Value::Number(_)) => {
                        m.insert(c.clone(), v.clone());
                        m.insert(format!("{c}_human"), cell(v, *how).into());
                    }
                    _ => { m.insert(c.clone(), v.clone()); }
                }
            }
            Value::Object(m)
        }).collect())
    }

    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(&self.to_json(false)).unwrap());
            return;
        }
        if let Some(n) = &self.note
            && self.cols.is_empty() {
                eprintln!("{n}");
                return;
            }
        let cells: Vec<Vec<String>> = self
            .rows
            .iter()
            .map(|r| r.iter().zip(&self.render).map(|(v, how)| cell(v, *how)).collect())
            .collect();
        let n = self.cols.len();
        let mut w: Vec<usize> = self.cols.iter().map(|c| c.chars().count()).collect();
        for r in &cells {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.chars().count());
            }
        }
        let numeric = |i: usize| self.render[i] != Render::Plain
            || self.rows.iter().all(|r| r[i].is_number() || r[i].is_null());
        let line = |r: &[String]| {
            let mut s = String::new();
            for (i, c) in r.iter().enumerate() {
                let pad = w[i] - c.chars().count();
                if i + 1 == n {
                    if numeric(i) { s.push_str(&" ".repeat(pad)); }
                    s.push_str(c);
                } else if numeric(i) {
                    s.push_str(&" ".repeat(pad));
                    s.push_str(c);
                    s.push_str("  ");
                } else {
                    s.push_str(c);
                    s.push_str(&" ".repeat(pad + 2));
                }
            }
            s
        };
        println!("{}", line(&self.cols));
        for r in &cells {
            println!("{}", line(r));
        }
        if let Some(n) = &self.note {
            eprintln!("{n}");
        }
    }
}

fn cell(v: &Value, how: Render) -> String {
    match (how, v) {
        (_, Value::Null) => String::new(),
        (Render::Bytes, Value::Number(n)) => bytes(n.as_i64().unwrap_or(0)),
        (Render::Date, Value::Number(n)) => date(n.as_i64().unwrap_or(0)),
        (Render::Pct, Value::Number(n)) => format!("{:.0}%", n.as_f64().unwrap_or(0.0)),
        (_, Value::String(s)) => s.clone(),
        (_, v) => v.to_string(),
    }
}

pub fn sql_value(v: rusqlite::types::ValueRef) -> Value {
    use rusqlite::types::ValueRef::*;
    match v {
        Null => Value::Null,
        Integer(i) => Value::from(i),
        Real(f) => Value::from(f),
        Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
        Blob(b) => Value::from(b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
    }
}
