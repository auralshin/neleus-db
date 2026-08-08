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
use crate::merkle::{
    ConsistencyProof, MerkleLeaf, MerkleProof, prove_consistency, prove_inclusion,
    root as log_root, root_from_spine, spine, spine_append, verify_consistency, verify_inclusion,
};
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

const CHECKPOINT_TAG: &[u8] = b"checkpoint:";
const CHECKPOINT_PAYLOAD_TAG: &[u8] = b"checkpoint_payload:";
const CHECKPOINT_LEAF_TAG: &[u8] = b"checkpoint_leaf:";
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 3;

/// Leaf for the append-only log over checkpointed commits.
pub fn checkpoint_leaf(commit: CommitHash) -> MerkleLeaf {
    MerkleLeaf::new(CHECKPOINT_LEAF_TAG, commit.as_bytes())
}

/// Check that `commit` was the `index`-th entry of a log with this root.
/// Offline: no store, no chain walk, `O(log J)`.
pub fn verify_commit_logged(root: Hash, commit: CommitHash, proof: &MerkleProof) -> bool {
    verify_inclusion(root, checkpoint_leaf(commit), proof)
}

/// Check that the log behind `old_root` is a prefix of the log behind
/// `new_root`: the history was appended to, never rewritten. Offline,
/// `O(log J)`. A linear chain cannot answer this without replaying everything.
pub fn verify_append_only(old_root: Hash, new_root: Hash, proof: &ConsistencyProof) -> bool {
    verify_consistency(old_root, new_root, proof)
}

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
    /// Merkle root over every commit checkpointed on this head so far, this
    /// one last (v2+). Lets a verifier check inclusion and append-onlyness in
    /// `O(log J)` instead of walking the chain.
    #[serde(default = "crate::merkle::empty_root")]
    pub log_root: Hash,
    /// Roots of the perfect subtrees the log decomposes into, largest first
    /// (v3+). Carrying it makes the next append `O(log J)` rather than a full
    /// rebuild; its width is the popcount of the entry count.
    #[serde(default)]
    pub log_spine: Vec<Hash>,
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

        // Extend the log from the predecessor's spine: O(log J), not a rebuild.
        // A predecessor carrying no spine falls back to recomputation rather
        // than producing a wrong root.
        let prev_state = match prev_hash {
            Some(h) => {
                let p = self.get(h)?;
                Some((p.log_spine, p.sequence as usize + 1))
            }
            None => None,
        };
        let (log_spine, count) = match prev_state {
            None => (spine_append(&[], 0, checkpoint_leaf(commit)), 1),
            Some((sp, n)) if sp.len() == (n as u64).count_ones() as usize => {
                (spine_append(&sp, n, checkpoint_leaf(commit)), n + 1)
            }
            Some((_, n)) => {
                let mut commits = self.logged_commits(head)?;
                commits.push(commit);
                let leaves: Vec<MerkleLeaf> =
                    commits.iter().copied().map(checkpoint_leaf).collect();
                debug_assert_eq!(leaves.len(), n + 1);
                (spine(&leaves), leaves.len())
            }
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
            log_root: root_from_spine(&log_spine, count),
            log_spine,
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

    /// Checkpointed commits for `head`, genesis first.
    pub fn logged_commits(&self, head: &str) -> Result<Vec<CommitHash>> {
        let mut out = Vec::new();
        let mut cursor = self.db.refs.checkpoint_get(head)?;
        while let Some(hash) = cursor {
            let cp = self.get(hash)?;
            out.push(cp.commit);
            cursor = cp.prev;
        }
        out.reverse();
        Ok(out)
    }

    /// `(log_root, proof)` showing the `index`-th checkpointed commit is in the
    /// log the current tip publishes.
    pub fn prove_commit_logged(&self, head: &str, index: usize) -> Result<(Hash, MerkleProof)> {
        let commits = self.logged_commits(head)?;
        let leaves: Vec<MerkleLeaf> = commits.iter().copied().map(checkpoint_leaf).collect();
        let proof = prove_inclusion(&leaves, index)
            .ok_or_else(|| anyhow!("no checkpoint at index {index} on head '{head}'"))?;
        Ok((log_root(&leaves), proof))
    }

    /// `(old_root, new_root, proof)` showing the log grew from `old_count`
    /// entries to its current size without rewriting anything.
    pub fn prove_append_only(
        &self,
        head: &str,
        old_count: usize,
    ) -> Result<(Hash, Hash, ConsistencyProof)> {
        let commits = self.logged_commits(head)?;
        let leaves: Vec<MerkleLeaf> = commits.iter().copied().map(checkpoint_leaf).collect();
        let proof = prove_consistency(&leaves, old_count)
            .ok_or_else(|| anyhow!("cannot prove consistency from {old_count} entries"))?;
        Ok((log_root(&leaves[..old_count]), log_root(&leaves), proof))
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

    /// The log must let a verifier check inclusion and append-onlyness with no
    /// store and no chain walk.
    #[test]
    fn log_proves_inclusion_and_append_only_offline() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        let mut commits = Vec::new();
        for i in 0..12 {
            commits.push(commit(&db, &format!("c{i}")));
            store.create("main", None).unwrap();
        }

        // Every checkpointed commit proves against the published root.
        for (i, c) in commits.iter().enumerate() {
            let (root, proof) = store.prove_commit_logged("main", i).unwrap();
            assert!(verify_commit_logged(root, *c, &proof), "index {i}");
            // Bound to its position: the same proof must not carry another commit.
            let other = commits[(i + 1) % commits.len()];
            if other != *c {
                assert!(!verify_commit_logged(root, other, &proof));
            }
        }

        // The tip checkpoint publishes that same root.
        let tip = store
            .get(db.refs.checkpoint_get("main").unwrap().unwrap())
            .unwrap();
        let (root, _) = store.prove_commit_logged("main", 0).unwrap();
        assert_eq!(tip.log_root, root, "tip must publish the current log root");

        // Append-onlyness between an old anchor and the current root.
        let (old_root, new_root, proof) = store.prove_append_only("main", 5).unwrap();
        assert!(verify_append_only(old_root, new_root, &proof));
        assert!(!verify_append_only(new_root, old_root, &proof));

        // Proof size is logarithmic, not linear in the chain.
        let (_, incl) = store.prove_commit_logged("main", 3).unwrap();
        assert!(
            incl.siblings.len() <= 4,
            "got {} hashes",
            incl.siblings.len()
        );
    }

    /// The incrementally-extended root must equal a from-scratch rebuild at
    /// every chain length, or the published anchor is wrong.
    #[test]
    fn incremental_log_root_matches_rebuild() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        for i in 0..40 {
            commit(&db, &format!("c{i}"));
            let h = store.create("main", None).unwrap();
            let cp = store.get(h).unwrap();
            let commits = store.logged_commits("main").unwrap();
            let leaves: Vec<crate::merkle::MerkleLeaf> =
                commits.iter().copied().map(checkpoint_leaf).collect();
            assert_eq!(
                cp.log_root,
                crate::merkle::root(&leaves),
                "incremental root diverged at length {}",
                i + 1
            );
            assert_eq!(
                cp.log_spine.len(),
                (commits.len() as u64).count_ones() as usize,
                "spine width must be the popcount of the length"
            );
            // And the published root still proves inclusion.
            let (root, proof) = store.prove_commit_logged("main", i).unwrap();
            assert_eq!(root, cp.log_root);
            assert!(verify_commit_logged(root, commits[i], &proof));
        }
    }

    /// A rewritten history must fail the append-only check even though every
    /// individual checkpoint still hashes correctly.
    #[test]
    fn rewritten_history_fails_append_only() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        for i in 0..8 {
            commit(&db, &format!("c{i}"));
            store.create("main", None).unwrap();
        }
        let (old_root, new_root, proof) = store.prove_append_only("main", 4).unwrap();
        assert!(verify_append_only(old_root, new_root, &proof));
        // An anchor from a different history of the same length is rejected.
        let forged = crate::merkle::root(
            &(0..4)
                .map(|i| checkpoint_leaf(crate::hash::hash_typed(b"forged:", &[i as u8])))
                .collect::<Vec<_>>(),
        );
        assert!(!verify_append_only(forged, new_root, &proof));
    }

    #[test]
    fn checkpoint_requires_existing_head() {
        let (_tmp, db) = test_db();
        let store = CheckpointStore::new(&db);
        assert!(store.create("main", None).is_err());
    }
}
