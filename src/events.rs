//! Append-only, hash-chained event log (`meta/events.jsonl`). Each entry links
//! to the previous by hash, so the log is tamper-evident: altering or dropping
//! an entry breaks the chain (verify with [`verify`]). It is the durable record
//! of policy violations and enforcement actions, and the source for the live
//! monitor feed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub timestamp: u64,
    /// Dotted event type, e.g. `policy.violation`.
    pub kind: String,
    /// Hex hash of the previous entry; empty at genesis.
    pub prev: String,
    /// Hex blake3 over this entry's canonical core (everything but `hash`).
    pub hash: String,
    pub data: Value,
}

fn log_path(db_root: &Path) -> PathBuf {
    db_root.join("meta").join("events.jsonl")
}

/// blake3 over the sorted-key JSON of the entry without its own `hash`.
/// `serde_json::Map` is BTree-backed here (no `preserve_order`), so the
/// encoding is deterministic.
fn entry_hash(seq: u64, timestamp: u64, kind: &str, prev: &str, data: &Value) -> String {
    let core = json!({
        "seq": seq,
        "timestamp": timestamp,
        "kind": kind,
        "prev": prev,
        "data": data,
    });
    let bytes = serde_json::to_vec(&core).expect("Value serializes");
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Read all events in order. Returns empty if the log does not exist.
pub fn read(db_root: &Path) -> Result<Vec<Event>> {
    match fs::read(log_path(db_root)) {
        Ok(bytes) => bytes
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Event>(l).map_err(Into::into))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}

/// Events with `seq > after` (the long-poll / live-feed cursor).
pub fn read_since(db_root: &Path, after: u64) -> Result<Vec<Event>> {
    Ok(read(db_root)?
        .into_iter()
        .filter(|e| e.seq > after)
        .collect())
}

/// Append one event, chaining it to the current tip. Callers must serialize
/// appends (the server holds its write lock); concurrent appends could fork the
/// chain.
pub fn append(db_root: &Path, kind: &str, data: Value) -> Result<Event> {
    let existing = read(db_root)?;
    let (seq, prev) = match existing.last() {
        Some(e) => (e.seq + 1, e.hash.clone()),
        None => (0, String::new()),
    };
    let timestamp = crate::clock::now_unix()?;
    let hash = entry_hash(seq, timestamp, kind, &prev, &data);
    let event = Event {
        seq,
        timestamp,
        kind: kind.to_string(),
        prev,
        hash,
        data,
    };

    let path = log_path(db_root);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_vec(&event)?;
    line.push(b'\n');
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?
        .write_all(&line)?;
    Ok(event)
}

/// Walk the chain, recomputing each hash and checking the back-links. Returns
/// the verified entry count.
pub fn verify(db_root: &Path) -> Result<u64> {
    let events = read(db_root)?;
    let mut prev = String::new();
    for (i, e) in events.iter().enumerate() {
        if e.seq != i as u64 {
            bail!("event {} has seq {}, expected {i}", e.hash, e.seq);
        }
        if e.prev != prev {
            bail!("event seq {} prev-link broken", e.seq);
        }
        let recomputed = entry_hash(e.seq, e.timestamp, &e.kind, &e.prev, &e.data);
        if recomputed != e.hash {
            bail!("event seq {} hash mismatch (tampered)", e.seq);
        }
        prev = e.hash.clone();
    }
    Ok(events.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn append_chains_and_verifies() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("meta")).unwrap();

        let a = append(root, "policy.violation", json!({"id": "x"})).unwrap();
        let b = append(root, "policy.violation", json!({"id": "y"})).unwrap();
        assert_eq!(a.seq, 0);
        assert_eq!(b.seq, 1);
        assert_eq!(b.prev, a.hash);
        assert_eq!(verify(root).unwrap(), 2);
        assert_eq!(read_since(root, 0).unwrap().len(), 1);
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("meta")).unwrap();
        append(root, "policy.violation", json!({"n": 1})).unwrap();
        append(root, "policy.violation", json!({"n": 2})).unwrap();

        // Rewrite the first line's data; the recomputed hash won't match.
        let raw = fs::read_to_string(log_path(root)).unwrap();
        let tampered = raw.replacen("\"n\":1", "\"n\":99", 1);
        fs::write(log_path(root), tampered).unwrap();
        assert!(verify(root).is_err());
    }
}
