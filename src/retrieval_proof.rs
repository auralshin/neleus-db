//! Proof bundles for search hits, verifiable offline with BLAKE3 + DAG-CBOR:
//!
//! ```text
//! commit hash = blake3("commit:" || commit_bytes)
//!   -> parents[0] chain to the introducing commit
//!   -> manifests contains manifest_hash = blake3("manifest:" || bytes)
//!   -> referenced blobs contain chunk_hash = blake3("blob:" || content)
//! ```
//!
//! Manifest type is pinned by canonical round-trip (decode -> re-encode
//! must reproduce the bytes).

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::canonical::{from_cbor, to_cbor};
use crate::commit::{COMMIT_TAG, Commit, CommitHash};
use crate::db::Database;
use crate::hash::{Hash, hash_blob, hash_typed};
use crate::manifest::{
    ChunkManifest, DocManifest, MANIFEST_TAG, ManifestReferences, RunManifest, SummaryManifest,
};

pub const CHUNK_PROOF_SCHEMA_VERSION: u32 = 1;

/// Cap on the ancestry walk while locating the introducing commit.
const MAX_PROOF_WALK: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkProof {
    pub schema_version: u32,
    /// The commit the retrieval ran against (head of the proof path).
    pub commit: CommitHash,
    /// Canonical commit bytes from `commit` down to the introducing commit,
    /// each linked to the next via `parents[0]`.
    pub commit_path: Vec<Vec<u8>>,
    pub manifest_hash: Hash,
    pub manifest_bytes: Vec<u8>,
    pub chunk_hash: Hash,
    /// The chunk content itself, when the prover chose to include it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_bytes: Option<Vec<u8>>,
    /// Content was requested but is erased (gone + covered by an erasure
    /// record): the proof degrades to commitment-only, `chunk_bytes` absent.
    #[serde(default, skip_serializing_if = "is_false")]
    pub content_erased: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Prove `chunk_hash` was retrievable at `commit`; walks first parents to
/// the introducing commit.
pub fn prove_chunk(
    db: &Database,
    commit: CommitHash,
    chunk_hash: Hash,
    include_content: bool,
) -> Result<ChunkProof> {
    let mut commit_path: Vec<Vec<u8>> = Vec::new();
    let mut cursor = commit;

    for _ in 0..MAX_PROOF_WALK {
        let bytes = db.commit_store.raw_commit_bytes(cursor)?;
        let c: Commit = from_cbor(&bytes)?;
        commit_path.push(bytes);

        for &manifest_hash in &c.manifests {
            let manifest_bytes = db.manifest_store.raw_manifest_bytes(manifest_hash)?;
            if manifest_references_chunk(&manifest_bytes, chunk_hash)?.is_some() {
                let mut content_erased = false;
                let chunk_bytes = if include_content {
                    match db.blob_store.get(chunk_hash) {
                        Ok(b) => Some(b),
                        // Erased + covered: emit a commitment-only proof.
                        Err(_) if crate::erasure::covers(&db.root, chunk_hash)? => {
                            content_erased = true;
                            None
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    None
                };
                return Ok(ChunkProof {
                    schema_version: CHUNK_PROOF_SCHEMA_VERSION,
                    commit,
                    commit_path,
                    manifest_hash,
                    manifest_bytes,
                    chunk_hash,
                    chunk_bytes,
                    content_erased,
                });
            }
        }

        match c.parents.first() {
            Some(&parent) => cursor = parent,
            None => break,
        }
    }

    Err(anyhow!(
        "no manifest reachable from commit {} references chunk {}",
        commit,
        chunk_hash
    ))
}

/// Verify a [`ChunkProof`] offline. Returns the kind of manifest that
/// anchored the chunk (`"doc"`, `"chunk"`, `"summary"`, `"run"`).
pub fn verify_chunk_proof(proof: &ChunkProof) -> Result<&'static str> {
    if proof.schema_version != CHUNK_PROOF_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported proof schema version {}",
            proof.schema_version
        ));
    }
    if proof.commit_path.is_empty() {
        return Err(anyhow!("proof has an empty commit path"));
    }

    // 1. Head of the path must hash to the claimed commit.
    let mut expected = proof.commit;
    let mut introducing: Option<Commit> = None;
    for (i, bytes) in proof.commit_path.iter().enumerate() {
        let actual = hash_typed(COMMIT_TAG, bytes);
        if actual != expected {
            return Err(anyhow!(
                "commit path link {i} hashes to {actual}, expected {expected}"
            ));
        }
        let c: Commit = from_cbor(bytes)
            .map_err(|e| anyhow!("commit path link {i} does not decode as a commit: {e}"))?;
        if i + 1 < proof.commit_path.len() {
            expected = *c
                .parents
                .first()
                .ok_or_else(|| anyhow!("commit path link {i} is a root but the path continues"))?;
        }
        introducing = Some(c);
    }
    let introducing = introducing.expect("non-empty path");

    // 2. The introducing commit must list the manifest.
    if !introducing.manifests.contains(&proof.manifest_hash) {
        return Err(anyhow!(
            "introducing commit does not reference manifest {}",
            proof.manifest_hash
        ));
    }

    // 3. Manifest bytes must hash to the claimed manifest hash.
    if hash_typed(MANIFEST_TAG, &proof.manifest_bytes) != proof.manifest_hash {
        return Err(anyhow!(
            "manifest bytes do not hash to {}",
            proof.manifest_hash
        ));
    }

    // 4. The manifest must reference the chunk.
    let kind =
        manifest_references_chunk(&proof.manifest_bytes, proof.chunk_hash)?.ok_or_else(|| {
            anyhow!(
                "manifest {} does not reference chunk {}",
                proof.manifest_hash,
                proof.chunk_hash
            )
        })?;

    // 5. If content is included, it must hash to the chunk hash; an
    //    erased-content proof must not also carry content.
    if proof.content_erased && proof.chunk_bytes.is_some() {
        return Err(anyhow!(
            "proof marked content-erased but carries chunk bytes"
        ));
    }
    if let Some(bytes) = &proof.chunk_bytes
        && hash_blob(bytes) != proof.chunk_hash
    {
        return Err(anyhow!("chunk bytes do not hash to {}", proof.chunk_hash));
    }

    Ok(kind)
}

/// Round-trip-identified manifest type + chunk reference check.
fn manifest_references_chunk(bytes: &[u8], chunk: Hash) -> Result<Option<&'static str>> {
    fn try_as<T: DeserializeOwned + Serialize + ManifestReferences>(
        bytes: &[u8],
        chunk: Hash,
    ) -> Option<bool> {
        let value: T = from_cbor(bytes).ok()?;
        let reencoded = to_cbor(&value).ok()?;
        if reencoded != bytes {
            return None;
        }
        Some(value.referenced_blobs().contains(&chunk))
    }

    if let Some(found) = try_as::<DocManifest>(bytes, chunk) {
        return Ok(found.then_some("doc"));
    }
    if let Some(found) = try_as::<ChunkManifest>(bytes, chunk) {
        return Ok(found.then_some("chunk"));
    }
    if let Some(found) = try_as::<SummaryManifest>(bytes, chunk) {
        return Ok(found.then_some("summary"));
    }
    if let Some(found) = try_as::<RunManifest>(bytes, chunk) {
        return Ok(found.then_some("run"));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::ChunkingSpec;

    fn test_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        (tmp, db)
    }

    fn ingest(db: &Database, text: &[u8]) -> (Hash, Hash) {
        let doc_hash = db
            .manifest_store
            .put_doc_manifest_from_bytes(
                &db.blob_store,
                "src".into(),
                text,
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 1024,
                    overlap: 0,
                },
                Some(1),
            )
            .unwrap();
        let doc: DocManifest = db.manifest_store.get_doc_manifest(doc_hash).unwrap();
        (doc_hash, doc.chunks[0])
    }

    #[test]
    fn prove_and_verify_roundtrip_with_content() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"provable chunk content");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();

        let proof = prove_chunk(&db, commit, chunk, true).unwrap();
        assert_eq!(verify_chunk_proof(&proof).unwrap(), "doc");
        assert_eq!(
            proof.chunk_bytes.as_deref(),
            Some(&b"provable chunk content"[..])
        );
    }

    #[test]
    fn proof_spans_ancestry_to_introducing_commit() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"old knowledge");
        let _c1 = db
            .create_commit_at_head("main", "agent", "intro", vec![doc_hash])
            .unwrap();
        let c2 = db
            .create_commit_at_head("main", "agent", "later", vec![])
            .unwrap();

        // Query ran at c2; the chunk was introduced at c1.
        let proof = prove_chunk(&db, c2, chunk, false).unwrap();
        assert_eq!(proof.commit_path.len(), 2);
        verify_chunk_proof(&proof).unwrap();
    }

    #[test]
    fn tampered_commit_bytes_fail() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"content");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();
        let mut proof = prove_chunk(&db, commit, chunk, false).unwrap();
        let last = proof.commit_path[0].len() - 1;
        proof.commit_path[0][last] ^= 0xff;
        assert!(verify_chunk_proof(&proof).is_err());
    }

    #[test]
    fn tampered_chunk_content_fails() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"content");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();
        let mut proof = prove_chunk(&db, commit, chunk, true).unwrap();
        proof.chunk_bytes = Some(b"forged content".to_vec());
        assert!(verify_chunk_proof(&proof).is_err());
    }

    #[test]
    fn swapped_chunk_hash_fails() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"content");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();
        let mut proof = prove_chunk(&db, commit, chunk, false).unwrap();
        proof.chunk_hash = hash_blob(b"some other chunk");
        assert!(verify_chunk_proof(&proof).is_err());
    }

    #[test]
    fn unreferenced_chunk_cannot_be_proven() {
        let (_tmp, db) = test_db();
        let (doc_hash, _chunk) = ingest(&db, b"content");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();
        let foreign = db.blob_store.put(b"never committed").unwrap();
        assert!(prove_chunk(&db, commit, foreign, false).is_err());
    }

    #[test]
    fn erased_content_yields_commitment_only_proof() {
        use crate::engine::Engine;
        use crate::erasure::{EraseOptions, erase_subject};
        use crate::manifest::ChunkMetadata;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();

        let (doc, commit) = engine
            .put_document(
                "main",
                "kb",
                b"subject content to be erased",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 64,
                    overlap: 0,
                },
                Some(ChunkMetadata {
                    subject: Some("u1".into()),
                    ..Default::default()
                }),
                "agent",
            )
            .unwrap();
        let chunk = engine
            .db()
            .manifest_store
            .get_doc_manifest(doc)
            .unwrap()
            .chunks[0];

        // Full proof while the content is present.
        let full = prove_chunk(engine.db(), commit, chunk, true).unwrap();
        assert!(full.chunk_bytes.is_some() && !full.content_erased);
        verify_chunk_proof(&full).unwrap();

        erase_subject(
            &engine,
            "u1",
            EraseOptions {
                reason: "request",
                requested_by: None,
                signer: None,
            },
        )
        .unwrap();

        // After erasure: commitment-only proof, content absent, still verifies.
        let proof = prove_chunk(engine.db(), commit, chunk, true).unwrap();
        assert!(proof.content_erased, "proof marked content-erased");
        assert!(proof.chunk_bytes.is_none(), "no content carried");
        assert_eq!(verify_chunk_proof(&proof).unwrap(), "doc");

        // Forging content back onto an erased-content proof is rejected.
        let mut forged = proof.clone();
        forged.chunk_bytes = Some(b"x".to_vec());
        assert!(verify_chunk_proof(&forged).is_err());
    }

    #[test]
    fn proof_bundle_roundtrips_through_cbor() {
        let (_tmp, db) = test_db();
        let (doc_hash, chunk) = ingest(&db, b"serialized proof");
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![doc_hash])
            .unwrap();
        let proof = prove_chunk(&db, commit, chunk, true).unwrap();
        let bytes = to_cbor(&proof).unwrap();
        let back: ChunkProof = from_cbor(&bytes).unwrap();
        assert_eq!(proof, back);
        verify_chunk_proof(&back).unwrap();
    }
}
