use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::blob_store::BlobStore;
use crate::clock::now_unix;
use crate::hash::Hash;
use crate::merkle::{
    MerkleLeaf, MerkleProof, prove_inclusion, root as merkle_root, verify_inclusion,
};
use crate::object_store::ObjectStore;

const MANIFEST_TAG: &[u8] = b"manifest:";
const MANIFEST_REF_LEAF_TAG: &[u8] = b"manifest_leaf:";
// v2 adds provider-metadata and RAG audit fields to RunManifest.
pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkingSpec {
    pub method: String,
    pub chunk_size: usize,
    pub overlap: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallRef {
    pub tool: String,
    pub input: Option<Hash>,
    pub output: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkManifest {
    pub schema_version: u32,
    pub chunk_text: Hash,
    pub start: usize,
    pub end: usize,
    pub embedding: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocManifest {
    pub schema_version: u32,
    pub source: String,
    pub created_at: u64,
    pub chunking: ChunkingSpec,
    pub chunks: Vec<Hash>,
    pub original: Hash,
}

/// A single AI model invocation: all inputs, outputs, retrieved context, and provider metadata.
///
/// Fields added in schema v2 use `skip_serializing_if` so v1 on-disk records are unaffected.
/// A v1 record decoded into this struct will have all new fields set to their defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: u32,
    /// Model identifier, e.g. `"claude-sonnet-4-6"`.
    pub model: String,
    /// Content-addressed blob of the primary user message.
    pub prompt: Hash,
    pub tool_calls: Vec<ToolCallRef>,
    pub inputs: Vec<Hash>,
    pub outputs: Vec<Hash>,
    pub started_at: u64,
    pub ended_at: u64,
    /// Provider name, e.g. `"anthropic"` or `"openai"` (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Content-addressed blob of the system prompt bytes (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<Hash>,
    /// Content-addressed blob of a sorted-keys JSON object containing model sampling parameters
    /// (e.g. `{"max_tokens": 1024, "temperature": 0.2}`). Stored separately so identical
    /// parameter sets deduplicate across runs (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_parameters: Option<Hash>,
    /// Hashes of `ChunkManifest` blobs retrieved from the knowledge base for this run.
    /// Closes the RAG audit loop: query → chunks → prompt → output → commit (v2+).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retrieved_chunks: Vec<Hash>,
    /// Caller-supplied SDK identifier, e.g. `"anthropic-python/0.40.0"` (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    /// Logical agent name or version, e.g. `"policy-reviewer-v1"` (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ManifestStore {
    objects: ObjectStore,
}

impl ManifestStore {
    pub fn new(objects: ObjectStore) -> Self {
        Self { objects }
    }

    /// Serialize and store any manifest type, returning its content-addressed hash.
    ///
    /// # Errors
    /// Returns an error if DAG-CBOR serialization or the object store write fails.
    pub fn put_manifest<T: Serialize>(&self, manifest: &T) -> Result<Hash> {
        self.objects.put_serialized(MANIFEST_TAG, manifest)
    }

    /// Retrieve and deserialize a manifest by hash.
    ///
    /// # Errors
    /// Returns an error if the hash is not found or the bytes cannot be deserialized as `T`.
    pub fn get_manifest<T: DeserializeOwned>(&self, hash: Hash) -> Result<T> {
        self.objects.get_deserialized_typed(MANIFEST_TAG, hash)
    }

    /// Typed retrieval for [`DocManifest`].
    pub fn get_doc_manifest(&self, hash: Hash) -> Result<DocManifest> {
        self.get_manifest(hash)
    }

    /// Typed retrieval for [`RunManifest`].
    pub fn get_run_manifest(&self, hash: Hash) -> Result<RunManifest> {
        self.get_manifest(hash)
    }

    /// Typed retrieval for [`ChunkManifest`].
    pub fn get_chunk_manifest(&self, hash: Hash) -> Result<ChunkManifest> {
        self.get_manifest(hash)
    }

    /// Canonical manifest bytes (decrypted/decompressed, not yet deserialized).
    /// GC uses these to identify a manifest's exact type by round-trip.
    pub fn raw_manifest_bytes(&self, hash: Hash) -> Result<Vec<u8>> {
        self.objects.get_typed_bytes(MANIFEST_TAG, hash)
    }

    /// Chunk `input_bytes`, store each chunk and the original as blobs, then store a
    /// [`DocManifest`] linking them all.
    ///
    /// # Arguments
    /// - `blob_store`: where raw chunk bytes are written
    /// - `source`: human-readable origin path or URI
    /// - `input_bytes`: full document bytes to chunk
    /// - `chunking`: chunk size and overlap parameters
    /// - `created_at`: Unix timestamp override; uses the current time when `None`
    ///
    /// # Errors
    /// Returns an error if chunking parameters are invalid, a blob write fails, or
    /// the system clock is set before the Unix epoch.
    pub fn put_doc_manifest_from_bytes(
        &self,
        blob_store: &BlobStore,
        source: String,
        input_bytes: &[u8],
        chunking: ChunkingSpec,
        created_at: Option<u64>,
    ) -> Result<Hash> {
        let original = blob_store.put(input_bytes)?;
        let chunks = chunk_fixed(input_bytes, chunking.chunk_size, chunking.overlap)?;

        let mut chunk_hashes = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            chunk_hashes.push(blob_store.put(&chunk)?);
        }

        let created_at = match created_at {
            Some(t) => t,
            None => now_unix()?,
        };
        let doc = DocManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            source,
            created_at,
            chunking,
            chunks: chunk_hashes,
            original,
        };
        self.put_manifest(&doc)
    }
}

/// Enumerate the content-addressed blobs that a manifest directly references.
///
/// The returned hashes are used to build the Merkle proof tree, so every blob
/// a verifier needs to check must appear here.
pub trait ManifestReferences {
    fn referenced_blobs(&self) -> Vec<Hash>;
}

impl ManifestReferences for DocManifest {
    fn referenced_blobs(&self) -> Vec<Hash> {
        let mut out = Vec::with_capacity(self.chunks.len() + 1);
        out.push(self.original);
        out.extend(self.chunks.iter().copied());
        out
    }
}

impl ManifestReferences for RunManifest {
    fn referenced_blobs(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        out.push(self.prompt);
        if let Some(h) = self.system_prompt {
            out.push(h);
        }
        if let Some(h) = self.model_parameters {
            out.push(h);
        }
        out.extend(self.inputs.iter().copied());
        out.extend(self.outputs.iter().copied());
        // Retrieved chunks are part of the Merkle proof so callers can prove
        // which knowledge-base chunks were in scope for this run.
        out.extend(self.retrieved_chunks.iter().copied());
        for call in &self.tool_calls {
            if let Some(h) = call.input {
                out.push(h);
            }
            if let Some(h) = call.output {
                out.push(h);
            }
        }
        out
    }
}

impl ManifestReferences for ChunkManifest {
    fn referenced_blobs(&self) -> Vec<Hash> {
        let mut out = vec![self.chunk_text];
        if let Some(h) = self.embedding {
            out.push(h);
        }
        out
    }
}

/// Build a domain-separated Merkle leaf for a single referenced blob.
pub fn manifest_reference_leaf(blob_hash: Hash) -> MerkleLeaf {
    MerkleLeaf::new(MANIFEST_REF_LEAF_TAG, blob_hash.as_bytes())
}

/// Compute the Merkle root over all blobs referenced by `manifest`.
pub fn manifest_reference_root<T: ManifestReferences>(manifest: &T) -> Hash {
    let leaves: Vec<MerkleLeaf> = manifest
        .referenced_blobs()
        .into_iter()
        .map(manifest_reference_leaf)
        .collect();
    merkle_root(&leaves)
}

/// Generate a Merkle inclusion proof for `blob_hash` within `manifest`'s reference set.
///
/// Returns `None` if `blob_hash` is not among the manifest's referenced blobs.
pub fn prove_blob_inclusion<T: ManifestReferences>(
    manifest: &T,
    blob_hash: Hash,
) -> Option<MerkleProof> {
    let refs = manifest.referenced_blobs();
    let idx = refs.iter().position(|h| *h == blob_hash)?;
    let leaves: Vec<MerkleLeaf> = refs.into_iter().map(manifest_reference_leaf).collect();
    prove_inclusion(&leaves, idx)
}

/// Verify a Merkle inclusion proof for `blob_hash` against `root`.
pub fn verify_blob_inclusion(root: Hash, blob_hash: Hash, proof: &MerkleProof) -> bool {
    verify_inclusion(root, manifest_reference_leaf(blob_hash), proof)
}

/// Free-function alias for [`ManifestStore::put_manifest`].
pub fn put_manifest<T: Serialize>(store: &ManifestStore, manifest: &T) -> Result<Hash> {
    store.put_manifest(manifest)
}

/// Free-function alias for [`ManifestStore::get_manifest`].
pub fn get_manifest<T: DeserializeOwned>(store: &ManifestStore, hash: Hash) -> Result<T> {
    store.get_manifest(hash)
}

/// Split `input` into fixed-size chunks of `chunk_size` bytes with `overlap` bytes of overlap.
///
/// # Errors
/// Returns an error if `chunk_size` is zero or `overlap >= chunk_size`.
pub fn chunk_fixed(input: &[u8], chunk_size: usize, overlap: usize) -> Result<Vec<Vec<u8>>> {
    if chunk_size == 0 {
        return Err(anyhow!("chunk_size must be > 0"));
    }
    if overlap >= chunk_size {
        return Err(anyhow!("overlap must be < chunk_size"));
    }
    if input.is_empty() {
        return Ok(vec![]);
    }

    let mut out = Vec::new();
    let mut start = 0usize;
    loop {
        let end = (start + chunk_size).min(input.len());
        out.push(input[start..end].to_vec());
        if end == input.len() {
            break;
        }
        start = end - overlap;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::object_store::ObjectStore;

    fn manifest_store(tmp: &TempDir) -> (ManifestStore, BlobStore) {
        let object_store = ObjectStore::new(tmp.path().join("objects"));
        object_store.ensure_dir().unwrap();
        let manifest_store = ManifestStore::new(object_store);

        let blob_store = BlobStore::new(tmp.path().join("blobs"));
        blob_store.ensure_dir().unwrap();

        (manifest_store, blob_store)
    }

    #[test]
    fn chunk_fixed_deterministic() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let a = chunk_fixed(input, 5, 1).unwrap();
        let b = chunk_fixed(input, 5, 1).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn chunk_fixed_handles_empty_input() {
        let out = chunk_fixed(b"", 10, 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn chunk_fixed_rejects_bad_overlap() {
        assert!(chunk_fixed(b"abc", 3, 3).is_err());
    }

    #[test]
    fn put_get_doc_manifest_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let doc = DocManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            source: "s".into(),
            created_at: 1,
            chunking: ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 10,
                overlap: 0,
            },
            chunks: vec![bs.put(b"chunk").unwrap()],
            original: bs.put(b"orig").unwrap(),
        };

        let h = ms.put_manifest(&doc).unwrap();
        let out: DocManifest = ms.get_manifest(h).unwrap();
        assert_eq!(doc, out);
    }

    #[test]
    fn put_manifest_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let doc = DocManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            source: "s".into(),
            created_at: 1,
            chunking: ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 10,
                overlap: 0,
            },
            chunks: vec![bs.put(b"chunk").unwrap()],
            original: bs.put(b"orig").unwrap(),
        };

        let a = ms.put_manifest(&doc).unwrap();
        let b = ms.put_manifest(&doc).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn put_run_manifest_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let run = RunManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            model: "m".into(),
            prompt: bs.put(b"prompt").unwrap(),
            tool_calls: vec![ToolCallRef {
                tool: "search".into(),
                input: None,
                output: None,
            }],
            inputs: vec![bs.put(b"in").unwrap()],
            outputs: vec![bs.put(b"out").unwrap()],
            started_at: 10,
            ended_at: 20,
            provider: Some("anthropic".into()),
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: vec![],
            sdk_version: Some("anthropic-python/0.40.0".into()),
            agent_id: Some("test-agent-v1".into()),
        };

        let h = ms.put_manifest(&run).unwrap();
        let out: RunManifest = ms.get_manifest(h).unwrap();
        assert_eq!(run, out);
    }

    #[test]
    fn put_doc_manifest_from_bytes_creates_chunks() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);
        let hash = ms
            .put_doc_manifest_from_bytes(
                &bs,
                "file.txt".into(),
                b"abcdefghij",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 4,
                    overlap: 1,
                },
                Some(123),
            )
            .unwrap();
        let doc: DocManifest = ms.get_manifest(hash).unwrap();
        assert_eq!(doc.chunks.len(), 3);
        assert_eq!(doc.created_at, 123);
    }

    #[test]
    fn doc_manifest_reference_proof_verifies() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let c1 = bs.put(b"c1").unwrap();
        let c2 = bs.put(b"c2").unwrap();
        let original = bs.put(b"orig").unwrap();
        let doc = DocManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            source: "src".into(),
            created_at: 1,
            chunking: ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 10,
                overlap: 0,
            },
            chunks: vec![c1, c2],
            original,
        };
        let _h = ms.put_manifest(&doc).unwrap();

        let root = manifest_reference_root(&doc);
        let proof = prove_blob_inclusion(&doc, c2).unwrap();
        assert!(verify_blob_inclusion(root, c2, &proof));
    }

    #[test]
    fn run_manifest_reference_proof_verifies() {
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let prompt = bs.put(b"prompt").unwrap();
        let input = bs.put(b"in").unwrap();
        let output = bs.put(b"out").unwrap();
        let run = RunManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            model: "m".into(),
            prompt,
            tool_calls: vec![],
            inputs: vec![input],
            outputs: vec![output],
            started_at: 1,
            ended_at: 2,
            provider: None,
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: vec![],
            sdk_version: None,
            agent_id: None,
        };
        let _h = ms.put_manifest(&run).unwrap();

        let root = manifest_reference_root(&run);
        let proof = prove_blob_inclusion(&run, input).unwrap();
        assert!(verify_blob_inclusion(root, input, &proof));
    }

    #[test]
    fn blob_not_referenced_has_no_proof() {
        let tmp = TempDir::new().unwrap();
        let (_, bs) = manifest_store(&tmp);
        let run = RunManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            model: "m".into(),
            prompt: bs.put(b"prompt").unwrap(),
            tool_calls: vec![],
            inputs: vec![],
            outputs: vec![],
            started_at: 1,
            ended_at: 2,
            provider: None,
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: vec![],
            sdk_version: None,
            agent_id: None,
        };
        let missing = bs.put(b"missing").unwrap();
        assert!(prove_blob_inclusion(&run, missing).is_none());
    }

    #[test]
    fn retrieved_chunks_included_in_reference_proof() {
        // RAG audit: retrieved chunks must appear in referenced_blobs so callers
        // can generate Merkle proofs that a specific chunk was in scope for a run.
        let tmp = TempDir::new().unwrap();
        let (ms, bs) = manifest_store(&tmp);

        let prompt = bs.put(b"prompt").unwrap();
        let chunk = bs.put(b"retrieved-chunk").unwrap();
        let run = RunManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            model: "m".into(),
            prompt,
            tool_calls: vec![],
            inputs: vec![],
            outputs: vec![],
            started_at: 1,
            ended_at: 2,
            provider: None,
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: vec![chunk],
            sdk_version: None,
            agent_id: None,
        };
        let _h = ms.put_manifest(&run).unwrap();

        let root = manifest_reference_root(&run);
        let proof = prove_blob_inclusion(&run, chunk).unwrap();
        assert!(verify_blob_inclusion(root, chunk, &proof));
    }

    #[test]
    fn v1_run_manifest_deserializes_with_new_fields_defaulted() {
        // v1 on-disk records (no new fields) must decode correctly with all v2
        // fields set to their defaults (None / empty Vec).
        use crate::canonical::{from_cbor, to_cbor};

        #[derive(Serialize)]
        struct RunManifestV1 {
            schema_version: u32,
            model: String,
            prompt: Hash,
            tool_calls: Vec<ToolCallRef>,
            inputs: Vec<Hash>,
            outputs: Vec<Hash>,
            started_at: u64,
            ended_at: u64,
        }

        let v1 = RunManifestV1 {
            schema_version: 1,
            model: "legacy-model".into(),
            prompt: Hash::zero(),
            tool_calls: vec![],
            inputs: vec![],
            outputs: vec![],
            started_at: 0,
            ended_at: 0,
        };
        let bytes = to_cbor(&v1).unwrap();
        let decoded: RunManifest = from_cbor(&bytes).unwrap();

        assert_eq!(decoded.model, "legacy-model");
        assert_eq!(decoded.schema_version, 1);
        assert!(decoded.provider.is_none());
        assert!(decoded.system_prompt.is_none());
        assert!(decoded.model_parameters.is_none());
        assert!(decoded.retrieved_chunks.is_empty());
        assert!(decoded.sdk_version.is_none());
        assert!(decoded.agent_id.is_none());
    }
}
