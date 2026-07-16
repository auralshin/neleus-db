//! Transparency-log checkpoints: an append-only hash chain over a head's
//! history, independent of the commit graph. Each checkpoint commits to its
//! predecessor, so history rewrites break the chain even with the commit
//! signing key. Optionally ed25519-signed; publishing the latest hash
//! externally anchors everything below it.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::clock::now_unix;
use crate::commit::CommitHash;
use crate::db::Database;
use crate::hash::{Hash, hash_typed};
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

const CHECKPOINT_TAG: &[u8] = b"checkpoint:";
const CHECKPOINT_PAYLOAD_TAG: &[u8] = b"checkpoint_payload:";
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub schema_version: u32,
    /// Previous checkpoint in the chain; `None` only for the genesis.
    pub prev: Option<Hash>,
    pub head: String,
    pub commit: CommitHash,
    pub sequence: u64,
    pub created_at: u64,
    /// ed25519 signature over the payload hash; optional but recommended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl Checkpoint {
    /// Hash of the checkpoint with signature fields cleared.
    pub fn payload_hash(&self) -> Result<Hash> {
        let unsigned = Checkpoint {
            signature: None,
            key_id: None,
            ..self.clone()
        };
        Ok(hash_typed(
            CHECKPOINT_PAYLOAD_TAG,
            &crate::canonical::to_cbor(&unsigned)?,
        ))
    }
}

/// Summary of a verified chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub length: u64,
    pub latest: Hash,
    pub genesis: Hash,
    pub signed: u64,
}

pub struct CheckpointStore<'a> {
    db: &'a Database,
}

impl<'a> CheckpointStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Append a checkpoint for `head`'s current commit.
    pub fn create(&self, head: &str, signer: Option<&Ed25519Signer>) -> Result<Hash> {
        let commit = self
            .db
            .refs
            .head_get(head)?
            .ok_or_else(|| anyhow!("head '{head}' has no commits to checkpoint"))?;

        let prev_hash = self.db.refs.checkpoint_get(head)?;
        let sequence = match prev_hash {
            Some(h) => self.get(h)?.sequence + 1,
            None => 0,
        };

        let mut checkpoint = Checkpoint {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            prev: prev_hash,
            head: head.to_string(),
            commit,
            sequence,
            created_at: now_unix()?,
            signature: None,
            key_id: None,
        };
        if let Some(signer) = signer {
            let payload = checkpoint.payload_hash()?;
            checkpoint.signature = Some(sign_raw(signer, payload.as_bytes()));
            checkpoint.key_id = Some(format!("ed25519:{}", signer.public_key_hex()));
        }

        let hash = self
            .db
            .object_store
            .put_serialized(CHECKPOINT_TAG, &checkpoint)?;
        self.db.refs.checkpoint_set(head, hash)?;
        Ok(hash)
    }

    pub fn get(&self, hash: Hash) -> Result<Checkpoint> {
        self.db
            .object_store
            .get_deserialized_typed(CHECKPOINT_TAG, hash)
    }

    /// Verify the full chain: sequences decrement to genesis 0, referenced
    /// commits exist, signatures check out under `verifier`;
    /// `require_signatures` rejects unsigned checkpoints.
    pub fn verify_chain(
        &self,
        head: &str,
        verifier: Option<&Ed25519Verifier>,
        require_signatures: bool,
    ) -> Result<ChainReport> {
        let latest = self
            .db
            .refs
            .checkpoint_get(head)?
            .ok_or_else(|| anyhow!("head '{head}' has no checkpoints"))?;

        let mut cursor = Some(latest);
        let mut expected_seq: Option<u64> = None;
        let mut length = 0u64;
        let mut signed = 0u64;
        let mut genesis = latest;

        while let Some(hash) = cursor {
            let cp = self.get(hash)?;
            if let Some(exp) = expected_seq
                && cp.sequence != exp
            {
                return Err(anyhow!(
                    "checkpoint {hash} has sequence {} (expected {exp}): chain tampered or truncated",
                    cp.sequence
                ));
            }
            expected_seq = cp.sequence.checked_sub(1);
            if cp.prev.is_none() && cp.sequence != 0 {
                return Err(anyhow!(
                    "checkpoint {hash} is genesis-shaped but has sequence {}",
                    cp.sequence
                ));
            }

            if !self.db.object_store.exists(cp.commit) {
                return Err(anyhow!(
                    "checkpoint {hash} references missing commit {}",
                    cp.commit
                ));
            }

            match (&cp.signature, verifier) {
                (Some(sig), Some(v)) => {
                    let payload = cp.payload_hash()?;
                    v.verify_raw(payload.as_bytes(), sig)
                        .map_err(|e| anyhow!("checkpoint {hash}: {e}"))?;
                    signed += 1;
                }
                (Some(_), None) => signed += 1, // present but unverified
                (None, _) if require_signatures => {
                    return Err(anyhow!("checkpoint {hash} is unsigned"));
                }
                (None, _) => {}
            }

            genesis = hash;
            length += 1;
            cursor = cp.prev;
        }

        Ok(ChainReport {
            length,
            latest,
            genesis,
            signed,
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::signing::generate_keypair_file;

    fn test_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        (tmp, db)
    }

    fn commit(db: &Database, msg: &str) -> Hash {
        db.create_commit_at_head("main", "agent", msg, vec![])
            .unwrap()
    }

    #[test]
    fn chain_grows_and_verifies() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);

        commit(&db, "c1");
        let cp1 = store.create("main", None).unwrap();
        commit(&db, "c2");
        let cp2 = store.create("main", None).unwrap();

        let report = store.verify_chain("main", None, false).unwrap();
        assert_eq!(report.length, 2);
        assert_eq!(report.latest, cp2);
        assert_eq!(report.genesis, cp1);
        assert_eq!(store.get(cp2).unwrap().prev, Some(cp1));
    }

    #[test]
    fn signed_chain_verifies_and_rejects_wrong_key() {
        let (tmp, db) = test_db();
        let key = tmp.path().join("k");
        let public_hex = generate_keypair_file(&key).unwrap();
        let signer = Ed25519Signer::from_seed_file(&key).unwrap();
        let store = CheckpointStore::new(&db);

        commit(&db, "c1");
        store.create("main", Some(&signer)).unwrap();

        let verifier = Ed25519Verifier::from_public_hex(&public_hex).unwrap();
        let report = store.verify_chain("main", Some(&verifier), true).unwrap();
        assert_eq!(report.signed, 1);

        let other_key = tmp.path().join("k2");
        let other_pub = generate_keypair_file(&other_key).unwrap();
        let wrong = Ed25519Verifier::from_public_hex(&other_pub).unwrap();
        assert!(store.verify_chain("main", Some(&wrong), true).is_err());
    }

    #[test]
    fn unsigned_checkpoint_fails_strict_mode() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        commit(&db, "c1");
        store.create("main", None).unwrap();
        assert!(store.verify_chain("main", None, true).is_err());
        store.verify_chain("main", None, false).unwrap();
    }

    #[test]
    fn checkpoint_requires_existing_head() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        assert!(store.create("main", None).is_err());
    }
}
