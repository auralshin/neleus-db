use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::blob_store::BlobStore;
use crate::hash::{Hash, hash_typed};
use crate::merkle::{MerkleProof, prove_inclusion, root as merkle_root, verify_inclusion};
use crate::object_store::ObjectStore;

const MANIFEST_TAG: &[u8] = b"manifest:";
const MANIFEST_REF_LEAF_TAG: &[u8] = b"manifest_leaf:";
const MANIFEST_SCHEMA_VERSION: u32 = 1;

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
    #[serde(default = "default_manifest_schema_version")]
    pub schema_version: u32,
    pub chunk_text: Hash,
    pub start: usize,
    pub end: usize,
    pub embedding: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocManifest {
    #[serde(default = "default_manifest_schema_version")]
    pub schema_version: u32,
    pub source: String,
    pub created_at: u64,
    pub chunking: ChunkingSpec,
    pub chunks: Vec<Hash>,
    pub original: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    #[serde(default = "default_manifest_schema_version")]
    pub schema_version: u32,
    pub model: String,
    pub prompt: Hash,
    pub tool_calls: Vec<ToolCallRef>,
    pub inputs: Vec<Hash>,
    pub outputs: Vec<Hash>,
    pub started_at: u64,
    pub ended_at: u64,
}

#[derive(Clone, Debug)]
pub struct ManifestStore {
    objects: ObjectStore,
}

impl ManifestStore {
    pub fn new(objects: ObjectStore) -> Self {
        Self { objects }
    }

    pub fn put_manifest<T: Serialize>(&self, manifest: &T) -> Result<Hash> {
        self.objects.put_serialized(MANIFEST_TAG, manifest)
    }

    pub fn get_manifest<T: DeserializeOwned>(&self, hash: Hash) -> Result<T> {
        self.objects.get_deserialized_typed(MANIFEST_TAG, hash)
    }

    pub fn get_doc_manifest(&self, hash: Hash) -> Result<DocManifest> {
        let mut manifest: DocManifest = self.get_manifest(hash)?;
        migrate_doc_manifest_in_place(&mut manifest);
        Ok(manifest)
    }

    pub fn get_run_manifest(&self, hash: Hash) -> Result<RunManifest> {
        let mut manifest: RunManifest = self.get_manifest(hash)?;
        migrate_run_manifest_in_place(&mut manifest);
        Ok(manifest)
    }

    pub fn get_chunk_manifest(&self, hash: Hash) -> Result<ChunkManifest> {
        let mut manifest: ChunkManifest = self.get_manifest(hash)?;
        migrate_chunk_manifest_in_place(&mut manifest);
        Ok(manifest)
    }

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

        let doc = DocManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            source,
            created_at: created_at.unwrap_or_else(now_unix),
            chunking,
            chunks: chunk_hashes,
            original,
        };
        self.put_manifest(&doc)
    }
}

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
        out.extend(self.inputs.iter().copied());
        out.extend(self.outputs.iter().copied());
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

pub fn manifest_reference_leaf_hash(blob_hash: Hash) -> Hash {
    hash_typed(MANIFEST_REF_LEAF_TAG, blob_hash.as_bytes())
}

pub fn manifest_reference_root<T: ManifestReferences>(manifest: &T) -> Hash {
    let leaves: Vec<Hash> = manifest
        .referenced_blobs()
        .into_iter()
        .map(manifest_reference_leaf_hash)
        .collect();
    merkle_root(&leaves)
}

pub fn prove_blob_inclusion<T: ManifestReferences>(
    manifest: &T,
    blob_hash: Hash,
) -> Option<MerkleProof> {
    let refs = manifest.referenced_blobs();
    let idx = refs.iter().position(|h| *h == blob_hash)?;
    let leaves: Vec<Hash> = refs.into_iter().map(manifest_reference_leaf_hash).collect();
    prove_inclusion(&leaves, idx)
}

pub fn verify_blob_inclusion(root: Hash, blob_hash: Hash, proof: &MerkleProof) -> bool {
    verify_inclusion(root, manifest_reference_leaf_hash(blob_hash), proof)
}

pub fn put_manifest<T: Serialize>(store: &ManifestStore, manifest: &T) -> Result<Hash> {
    store.put_manifest(manifest)
}

pub fn get_manifest<T: DeserializeOwned>(store: &ManifestStore, hash: Hash) -> Result<T> {
    store.get_manifest(hash)
}

pub fn migrate_doc_manifest(mut manifest: DocManifest) -> DocManifest {
    migrate_doc_manifest_in_place(&mut manifest);
    manifest
}

pub fn migrate_run_manifest(mut manifest: RunManifest) -> RunManifest {
    migrate_run_manifest_in_place(&mut manifest);
    manifest
}

pub fn migrate_chunk_manifest(mut manifest: ChunkManifest) -> ChunkManifest {
    migrate_chunk_manifest_in_place(&mut manifest);
    manifest
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before epoch")
        .as_secs()
}

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

fn default_manifest_schema_version() -> u32 {
    MANIFEST_SCHEMA_VERSION
}

fn migrate_doc_manifest_in_place(manifest: &mut DocManifest) {
    if manifest.schema_version == 0 {
        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
    }
}

fn migrate_run_manifest_in_place(manifest: &mut RunManifest) {
    if manifest.schema_version == 0 {
        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
    }
}

fn migrate_chunk_manifest_in_place(manifest: &mut ChunkManifest) {
    if manifest.schema_version == 0 {
        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
    }
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
    fn now_unix_progresses_or_stays() {
        let a = now_unix();
        let b = now_unix();
        assert!(b >= a);
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
        };
        let missing = bs.put(b"missing").unwrap();
        assert!(prove_blob_inclusion(&run, missing).is_none());
    }

    #[test]
    fn migration_fills_legacy_schema_version() {
        let legacy = DocManifest {
            schema_version: 0,
            source: "s".into(),
            created_at: 0,
            chunking: ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 2,
                overlap: 0,
            },
            chunks: vec![],
            original: Hash::zero(),
        };
        let migrated = migrate_doc_manifest(legacy);
        assert_eq!(migrated.schema_version, MANIFEST_SCHEMA_VERSION);
    }
}
