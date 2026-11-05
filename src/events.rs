//! Append-only, hash-chained event log (`meta/events.jsonl`). Each entry links
//! to the previous by hash, so the log is tamper-evident: altering or dropping
//! an entry breaks the chain (verify with [`verify`]). It is the durable record
//! of policy violations and enforcement actions, and the source for the live
//! monitor feed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
        // An unterminated last line is a torn append and is not an entry.
        Ok(bytes) => bytes[..bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)]
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Event>(l).map_err(Into::into))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}

/// Tail window scanned for the last entry. Comfortably larger than any event
/// this crate writes; a longer final line falls back to a full read.
const TIP_WINDOW: u64 = 64 * 1024;

/// Last entry, without parsing the whole log.
///
/// `append` only needs the tip, and reading every line to find it made each
/// append cost O(log length), so a write path that records an event per call
/// (a monitor-mode policy, say) degraded quadratically as the log grew.
fn read_tip(db_root: &Path) -> Result<Option<Event>> {
    use std::io::{Read, Seek, SeekFrom};

    let path = log_path(db_root);
    let mut f = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let window = len.min(TIP_WINDOW);
    f.seek(SeekFrom::Start(len - window))?;
    let mut buf = vec![0u8; window as usize];
    f.read_exact(&mut buf)?;

    // Only terminated lines count: an unterminated tail is a torn append. A
    // window that caught no earlier line break may have split a line, so
    // re-read in full.
    let text = String::from_utf8_lossy(&buf);
    let whole = &text[..text.rfind('\n').map_or(0, |i| i + 1)];
    let last = whole.lines().rfind(|l| !l.trim().is_empty());
    match last {
        Some(line) if window == len || whole[..whole.len() - line.len() - 1].contains('\n') => {
            Ok(Some(serde_json::from_str(line)?))
        }
        _ => Ok(read(db_root)?.pop()),
    }
}

/// Drop an unterminated last line left by a crash mid-append, so the next
/// entry does not fuse with it. Called under the append lock.
fn truncate_torn_tail(path: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    let mut last = [0u8; 1];
    f.seek(SeekFrom::Start(len - 1))?;
    f.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let mut bytes = Vec::new();
    f.seek(SeekFrom::Start(0))?;
    f.read_to_end(&mut bytes)?;
    let keep = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i as u64 + 1);
    f.set_len(keep)?;
    crate::atomic::maybe_sync_file(&f)?;
    Ok(())
}

/// Newest entry's sequence, or `None` if empty. Reads a tail window, not the log.
pub fn tip_seq(db_root: &Path) -> Result<Option<u64>> {
    Ok(read_tip(db_root)?.map(|e| e.seq))
}

/// Newest entry's `(seq, hash)`, for a checkpoint to pin.
pub fn tip(db_root: &Path) -> Result<Option<(u64, crate::hash::Hash)>> {
    read_tip(db_root)?
        .map(|e| Ok((e.seq, e.hash.parse()?)))
        .transpose()
}

/// Events with `seq > after` (the long-poll / live-feed cursor).
pub fn read_since(db_root: &Path, after: u64) -> Result<Vec<Event>> {
    Ok(read(db_root)?
        .into_iter()
        .filter(|e| e.seq > after)
        .collect())
}

/// Append one event, chaining it to the current tip.
///
/// Takes a cross-process lock: the server's write mutex only serializes its own
/// threads, and a CLI command (or a second server) appending concurrently would
/// mint a duplicate `seq`, after which [`verify`] fails permanently on an
/// append-only file.
pub fn append(db_root: &Path, kind: &str, data: Value) -> Result<Event> {
    let dir = db_root.join("meta");
    fs::create_dir_all(&dir)?;
    let _lock = crate::lock::flock_exclusive(dir.join(".events.lock"), Duration::from_secs(10))?;
    truncate_torn_tail(&log_path(db_root))?;

    let (seq, prev) = match read_tip(db_root)? {
        Some(tip) => (tip.seq + 1, tip.hash),
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
    let created = !path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    file.write_all(&line)?;
    crate::atomic::maybe_sync_file(&file)?;
    if created {
        crate::atomic::maybe_sync_dir(&dir)?;
    }
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
    fn tip_survives_an_entry_larger_than_the_tail_window() {
        // The tail scan reads a fixed window. An entry longer than it would
        // leave the window holding a fragment with no line break, so the scan
        // must fall back to a full read rather than chain onto garbage.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        append(root, "small", json!({"i": 0})).unwrap();
        let big = "x".repeat(TIP_WINDOW as usize + 1024);
        append(root, "big", json!({"blob": big})).unwrap();
        append(root, "after", json!({"i": 2})).unwrap();
        assert_eq!(verify(root).unwrap(), 3, "chain must stay intact");
    }

    #[test]
    fn torn_tail_is_repaired_on_append() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let first = append(root, "a", json!({})).unwrap();
        let path = log_path(root);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"seq":1,"timestamp":0,"kind":"torn"#)
            .unwrap();
        drop(f);
        assert_eq!(tip(root).unwrap().unwrap().0, first.seq);
        let next = append(root, "b", json!({})).unwrap();
        assert_eq!(next.seq, 1);
        assert_eq!(next.prev, first.hash);
        assert_eq!(verify(root).unwrap(), 2);
    }

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
