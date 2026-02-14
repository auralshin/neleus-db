use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::canonical::{from_cbor, to_cbor};
use crate::hash::Hash;

const WAL_SCHEMA_VERSION: u32 = 1;

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
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let safe_op = format!("{:?}", entry.op).to_lowercase();
        let path = self.root.join(format!("{ts}-{safe_op}.wal"));
        let bytes = to_cbor(entry)?;
        write_atomic(&path, &bytes)
            .with_context(|| format!("failed to write WAL entry {}", path.display()))?;
        Ok(path)
    }

    pub fn begin(&self, op: &str, payload: &[u8]) -> Result<PathBuf> {
        self.ensure_dir()?;
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let safe_op = op.replace('/', "_");
        let path = self.root.join(format!("{ts}-{safe_op}.wal"));
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
                        validate_ref_name(&name)?;
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
                        validate_ref_name(&name)?;
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
                    // Immutable state objects are content addressed; ref mutation is recovered
                    // separately, so an interrupted state mutation WAL can be safely discarded.
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

fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("reference name cannot be empty"));
    }
    if name.starts_with('/') || name.contains("..") || name.contains('\0') {
        return Err(anyhow!("unsafe reference name in WAL: {name}"));
    }
    Ok(())
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
}
