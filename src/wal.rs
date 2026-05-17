use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::canonical::{from_cbor, to_cbor};
use crate::hash::Hash;
use crate::refs::validate_ref_name;

const WAL_SCHEMA_VERSION: u32 = 1;

/// Per-process counter appended to WAL filenames. Combined with PID and a
/// nanosecond timestamp, this guarantees uniqueness even under bursts that
/// share a wall-clock nanosecond.
static WAL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn wal_filename(op: &str) -> Result<String> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let seq = WAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(format!("{ts}-{pid}-{seq}-{op}.wal"))
}

#[derive(Clone, Debug)]
pub struct Wal {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalOp {
    RefHeadSet,
    RefStateSet,
    StateSet,
    StateDel,
    StateCompact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalPayload {
    RefUpdate { name: String, hash: Hash },
    StateMutation { root: Hash, key_len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalEntry {
    pub schema_version: u32,
    pub op: WalOp,
    pub payload: WalPayload,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalRecoveryReport {
    pub replayed: usize,
    pub rolled_back: usize,
}

impl Wal {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("failed creating WAL dir {}", self.root.display()))?;
        Ok(())
    }

    pub fn begin_entry(&self, entry: &WalEntry) -> Result<PathBuf> {
        self.ensure_dir()?;
        let safe_op = format!("{:?}", entry.op).to_lowercase();
        let path = self.root.join(wal_filename(&safe_op)?);
        let bytes = to_cbor(entry)?;
        write_atomic(&path, &bytes)
            .with_context(|| format!("failed to write WAL entry {}", path.display()))?;
        Ok(path)
    }

    pub fn begin(&self, op: &str, payload: &[u8]) -> Result<PathBuf> {
        self.ensure_dir()?;
        let safe_op = op.replace('/', "_");
        let path = self.root.join(wal_filename(&safe_op)?);
        write_atomic(&path, payload)
            .with_context(|| format!("failed to write WAL entry {}", path.display()))?;
        Ok(path)
    }

    pub fn end(&self, wal_path: &Path) -> Result<()> {
        if wal_path.exists() {
            fs::remove_file(wal_path)
                .with_context(|| format!("failed removing WAL entry {}", wal_path.display()))?;
        }
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<PathBuf>> {
        self.ensure_dir()?;
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|x| x == "wal").unwrap_or(false) {
                out.push(path);
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn recover_refs(&self, refs_root: &Path) -> Result<WalRecoveryReport> {
        self.ensure_dir()?;
        fs::create_dir_all(refs_root.join("heads"))?;
        fs::create_dir_all(refs_root.join("states"))?;

        let mut report = WalRecoveryReport::default();
        for path in self.pending()? {
            let raw = fs::read(&path)
                .with_context(|| format!("failed reading WAL {}", path.display()))?;

            let entry = match from_cbor::<WalEntry>(&raw) {
                Ok(entry) => entry,
                Err(_) => {
                    // Roll back malformed or legacy opaque entries.
                    self.end(&path)?;
                    report.rolled_back += 1;
                    continue;
                }
            };

            if entry.schema_version != WAL_SCHEMA_VERSION {
                self.end(&path)?;
                report.rolled_back += 1;
                continue;
            }

            match entry.op {
                WalOp::RefHeadSet => {
                    if let WalPayload::RefUpdate { name, hash } = entry.payload {
                        // A stricter validator may now reject names that an
                        // older writer accepted. Treat such entries as
                        // malformed-on-replay and roll back rather than
                        // failing `Database::open` outright.
                        if validate_ref_name(&name).is_err() {
                            self.end(&path)?;
                            report.rolled_back += 1;
                            continue;
                        }
                        write_atomic(
                            &refs_root.join("heads").join(name),
                            format!("{hash}\n").as_bytes(),
                        )?;
                        report.replayed += 1;
                    } else {
                        report.rolled_back += 1;
                    }
                }
                WalOp::RefStateSet => {
                    if let WalPayload::RefUpdate { name, hash } = entry.payload {
                        if validate_ref_name(&name).is_err() {
                            self.end(&path)?;
                            report.rolled_back += 1;
                            continue;
                        }
                        write_atomic(
                            &refs_root.join("states").join(name),
                            format!("{hash}\n").as_bytes(),
                        )?;
                        report.replayed += 1;
                    } else {
                        report.rolled_back += 1;
                    }
                }
                WalOp::StateSet | WalOp::StateDel | WalOp::StateCompact => {
                    // State WAL entries are forensic only and are NEVER replayed.
                    //
                    // State objects are content-addressed and immutable; an interrupted
                    // state mutation has at most written partial garbage objects (which
                    // are unreachable, since no ref points at them) and never advanced
                    // the state ref. The real commit point is the ref CAS, which is
                    // recovered via the `RefStateSet` arm above.
                    //
                    // If a future change ever needs to replay state ops, it MUST also
                    // confirm idempotency — applying the recorded mutation twice when a
                    // prior partial run already produced the resulting object would
                    // succeed in CAS (no-op) but a partial state graph could leave
                    // orphans. Replay is a separate, deliberate design choice.
                    report.rolled_back += 1;
                }
            }

            self.end(&path)?;
        }

        Ok(report)
    }

    pub fn make_ref_entry(op: WalOp, name: &str, hash: Hash) -> WalEntry {
        WalEntry {
            schema_version: WAL_SCHEMA_VERSION,
            op,
            payload: WalPayload::RefUpdate {
                name: name.to_string(),
                hash,
            },
        }
    }

    pub fn make_state_entry(op: WalOp, root: Hash, key_len: usize) -> WalEntry {
        WalEntry {
            schema_version: WAL_SCHEMA_VERSION,
            op,
            payload: WalPayload::StateMutation { root, key_len },
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_blob;

    #[test]
    fn wal_begin_end_cycle() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path());
        let p = wal.begin("op", b"payload").unwrap();
        assert!(p.exists());
        wal.end(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn wal_lists_pending_entries() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path());
        let _a = wal.begin("a", b"1").unwrap();
        let _b = wal.begin("b", b"2").unwrap();
        assert_eq!(wal.pending().unwrap().len(), 2);
    }

    #[test]
    fn wal_recovers_ref_head_set() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path().join("wal"));
        wal.ensure_dir().unwrap();

        let h = hash_blob(b"commit");
        let entry = Wal::make_ref_entry(WalOp::RefHeadSet, "main", h);
        let _p = wal.begin_entry(&entry).unwrap();

        let report = wal.recover_refs(&dir.path().join("refs")).unwrap();
        assert_eq!(report.replayed, 1);
        let s = fs::read_to_string(dir.path().join("refs/heads/main")).unwrap();
        assert_eq!(s.trim(), h.to_string());
        assert!(wal.pending().unwrap().is_empty());
    }

    #[test]
    fn wal_rolls_back_malformed_entry() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path().join("wal"));
        wal.ensure_dir().unwrap();
        fs::write(dir.path().join("wal/bad.wal"), b"garbage").unwrap();

        let report = wal.recover_refs(&dir.path().join("refs")).unwrap();
        assert_eq!(report.rolled_back, 1);
        assert!(wal.pending().unwrap().is_empty());
    }

    /// Regression for issue #4: WAL filenames must be unique even when
    /// many entries are begun in rapid succession. The pre-fix scheme
    /// included only `{nanos}-{op}` and could collide on bursts.
    #[test]
    fn wal_begin_produces_unique_filenames_under_burst() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path().join("wal"));
        wal.ensure_dir().unwrap();

        let mut paths = Vec::new();
        for _ in 0..1000 {
            let p = wal.begin("op", b"x").unwrap();
            paths.push(p);
        }
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(
            unique.len(),
            paths.len(),
            "WAL filename collision under burst"
        );
        assert_eq!(wal.pending().unwrap().len(), 1000);
    }

    /// Regression: a WAL entry written under the previous (laxer) ref-name
    /// validator must not block `Database::open` after a validator tightening.
    /// `recover_refs` rolls back invalid-on-replay entries instead of
    /// propagating the error.
    #[test]
    fn wal_rolls_back_ref_entry_with_newly_invalid_name() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path().join("wal"));
        wal.ensure_dir().unwrap();

        // `-flag-like` is rejected by the new validator. Construct the
        // entry directly (bypassing `make_ref_entry` if it validated) so we
        // simulate a stale on-disk entry from an older build.
        let entry = WalEntry {
            schema_version: WAL_SCHEMA_VERSION,
            op: WalOp::RefHeadSet,
            payload: WalPayload::RefUpdate {
                name: "-flag-like".into(),
                hash: hash_blob(b"h"),
            },
        };
        let raw = to_cbor(&entry).unwrap();
        let path = dir.path().join("wal").join("1-1-0-refheadset.wal");
        fs::write(&path, raw).unwrap();

        let report = wal.recover_refs(&dir.path().join("refs")).unwrap();
        assert_eq!(report.replayed, 0);
        assert_eq!(report.rolled_back, 1);
        assert!(wal.pending().unwrap().is_empty());
    }

    /// Regression: state WAL entries are forensic only and must always be
    /// rolled back on recovery. A future change that replays them would
    /// break the invariant; this test fails loudly if that ever happens.
    #[test]
    fn state_wal_entries_are_always_rolled_back() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::new(dir.path().join("wal"));
        wal.ensure_dir().unwrap();

        let dummy_root = hash_blob(b"r");
        for op in [WalOp::StateSet, WalOp::StateDel, WalOp::StateCompact] {
            let entry = Wal::make_state_entry(op, dummy_root, 1);
            let _ = wal.begin_entry(&entry).unwrap();
        }

        let report = wal.recover_refs(&dir.path().join("refs")).unwrap();
        assert_eq!(report.replayed, 0);
        assert_eq!(report.rolled_back, 3);
        assert!(wal.pending().unwrap().is_empty());
    }
}
