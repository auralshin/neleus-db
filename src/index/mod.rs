use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::blob_store::BlobStore;
use crate::commit::{CommitHash, CommitStore};
use crate::hash::{Hash, hash_typed};
use crate::manifest::{ChunkManifest, DocManifest, ManifestStore};

const INDEX_SCHEMA_VERSION: u32 = 1;
const INDEX_TAG: &[u8] = b"index:";

pub type IndexVersionHash = Hash;

pub trait IndexBuilder {
    fn build(&self, root: CommitHash) -> Result<IndexVersionHash>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexChunk {
    pub chunk_hash: Hash,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Posting {
    pub chunk_hash: Hash,
    pub tf: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchIndex {
    pub schema_version: u32,
    pub commit: CommitHash,
    pub built_at: u64,
    pub chunks: Vec<IndexChunk>,
    pub semantic_docs: u32,
    pub avg_doc_len: f32,
    pub semantic_doc_len: BTreeMap<String, u32>,
    pub semantic_doc_freq: BTreeMap<String, u32>,
    pub semantic_postings: BTreeMap<String, Vec<Posting>>,
    pub vector_dim: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub chunk_hash: Hash,
    pub score: f32,
    pub text_preview: String,
}

#[derive(Debug, Clone)]
pub struct SearchIndexStore {
    root: PathBuf,
}

impl SearchIndexStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("failed creating index root {}", self.root.display()))?;
        Ok(())
    }

    pub fn build_for_head(
        &self,
        head: CommitHash,
        commit_store: &CommitStore,
        manifest_store: &ManifestStore,
        blob_store: &BlobStore,
    ) -> Result<IndexVersionHash> {
        self.ensure_dir()?;

        let commit = commit_store.get_commit(head)?;
        let mut chunks: BTreeMap<Hash, IndexChunk> = BTreeMap::new();

        for manifest_hash in commit.manifests {
            if let Ok(doc) = manifest_store.get_doc_manifest(manifest_hash) {
                self.add_doc_chunks(&doc, blob_store, &mut chunks)?;
            }
            if let Ok(chunk_manifest) = manifest_store.get_chunk_manifest(manifest_hash) {
                self.add_chunk_manifest(&chunk_manifest, blob_store, &mut chunks)?;
            }
        }

        let mut chunk_vec: Vec<IndexChunk> = chunks.into_values().collect();
        chunk_vec.sort_by(|a, b| a.chunk_hash.cmp(&b.chunk_hash));

        let (semantic_docs, avg_doc_len, semantic_doc_len, semantic_doc_freq, semantic_postings) =
            build_semantic_tables(&chunk_vec);

        let vector_dim = chunk_vec
            .iter()
            .find_map(|c| c.embedding.as_ref().map(|v| v.len()));

        let index = SearchIndex {
            schema_version: INDEX_SCHEMA_VERSION,
            commit: head,
            built_at: now_unix(),
            chunks: chunk_vec,
            semantic_docs,
            avg_doc_len,
            semantic_doc_len,
            semantic_doc_freq,
            semantic_postings,
            vector_dim,
        };

        self.write_index(&index)
    }

    pub fn read_index(&self, commit: CommitHash) -> Result<SearchIndex> {
        let path = self.index_path(commit);
        let bytes = fs::read(&path)
            .with_context(|| format!("missing index for {} at {}", commit, path.display()))?;
        let index: SearchIndex = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed decoding index {}", path.display()))?;
        if index.schema_version != INDEX_SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported index schema version: {}",
                index.schema_version
            ));
        }
        Ok(index)
    }

    pub fn semantic_search(
        &self,
        commit: CommitHash,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<SearchHit>> {
        let index = self.read_index(commit)?;
        Ok(semantic_search_index(&index, query, top_k))
    }

    pub fn vector_search(
        &self,
        commit: CommitHash,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<SearchHit>> {
        let index = self.read_index(commit)?;
        vector_search_index(&index, query_embedding, top_k)
    }

    pub fn parse_embedding(bytes: &[u8]) -> Result<Vec<f32>> {
        parse_embedding(bytes)
    }

    fn write_index(&self, index: &SearchIndex) -> Result<IndexVersionHash> {
        let dir = self.commit_dir(index.commit);
        fs::create_dir_all(&dir)?;
        let path = self.index_path(index.commit);

        let bytes = serde_json::to_vec_pretty(index)?;
        write_atomic(&path, &bytes)?;

        Ok(hash_typed(INDEX_TAG, &bytes))
    }

    fn add_doc_chunks(
        &self,
        doc: &DocManifest,
        blob_store: &BlobStore,
        chunks: &mut BTreeMap<Hash, IndexChunk>,
    ) -> Result<()> {
        for chunk_hash in &doc.chunks {
            if chunks.contains_key(chunk_hash) {
                continue;
            }
            let bytes = blob_store.get(*chunk_hash)?;
            let text = String::from_utf8_lossy(&bytes).to_string();
            chunks.insert(
                *chunk_hash,
                IndexChunk {
                    chunk_hash: *chunk_hash,
                    text,
                    embedding: None,
                },
            );
        }
        Ok(())
    }

    fn add_chunk_manifest(
        &self,
        manifest: &ChunkManifest,
        blob_store: &BlobStore,
        chunks: &mut BTreeMap<Hash, IndexChunk>,
    ) -> Result<()> {
        let text_bytes = blob_store.get(manifest.chunk_text)?;
        let text = String::from_utf8_lossy(&text_bytes).to_string();
        let embedding = if let Some(embedding_hash) = manifest.embedding {
            let raw = blob_store.get(embedding_hash)?;
            Some(parse_embedding(&raw)?)
        } else {
            None
        };

        chunks
            .entry(manifest.chunk_text)
            .and_modify(|c| {
                c.text = text.clone();
                if embedding.is_some() {
                    c.embedding = embedding.clone();
                }
            })
            .or_insert(IndexChunk {
                chunk_hash: manifest.chunk_text,
                text,
                embedding,
            });

        Ok(())
    }

    fn commit_dir(&self, commit: CommitHash) -> PathBuf {
        self.root.join(commit.to_string())
    }

    fn index_path(&self, commit: CommitHash) -> PathBuf {
        self.commit_dir(commit).join("search_index.json")
    }
}

impl IndexBuilder for SearchIndexStore {
    fn build(&self, _root: CommitHash) -> Result<IndexVersionHash> {
        Err(anyhow!(
            "build(root) requires stores; use build_for_head(root, ...)"
        ))
    }
}

fn parse_embedding(bytes: &[u8]) -> Result<Vec<f32>> {
    if let Ok(v) = crate::canonical::from_cbor::<Vec<f32>>(bytes) {
        return Ok(v);
    }
    if let Ok(v64) = crate::canonical::from_cbor::<Vec<f64>>(bytes) {
        return Ok(v64.into_iter().map(|x| x as f32).collect());
    }
    if let Ok(v) = serde_json::from_slice::<Vec<f32>>(bytes) {
        return Ok(v);
    }
    if let Ok(v64) = serde_json::from_slice::<Vec<f64>>(bytes) {
        return Ok(v64.into_iter().map(|x| x as f32).collect());
    }
    Err(anyhow!(
        "embedding bytes are not supported (expected CBOR/JSON vec)"
    ))
}

fn semantic_search_index(index: &SearchIndex, query: &str, top_k: usize) -> Vec<SearchHit> {
    if top_k == 0 {
        return Vec::new();
    }

    let query_terms = tokenize(query);
    if query_terms.is_empty() {
        return Vec::new();
    }

    let mut scores: BTreeMap<Hash, f32> = BTreeMap::new();
    let n_docs = index.semantic_docs.max(1) as f32;
    let avg_dl = if index.avg_doc_len > 0.0 {
        index.avg_doc_len
    } else {
        1.0
    };
    let k1 = 1.5f32;
    let b = 0.75f32;

    for term in query_terms {
        let df = *index.semantic_doc_freq.get(&term).unwrap_or(&0) as f32;
        if df <= 0.0 {
            continue;
        }

        let idf = ((n_docs - df + 0.5) / (df + 0.5) + 1.0).ln();
        if let Some(postings) = index.semantic_postings.get(&term) {
            for posting in postings {
                let dl = *index
                    .semantic_doc_len
                    .get(&posting.chunk_hash.to_string())
                    .unwrap_or(&0) as f32;
                let tf = posting.tf as f32;
                let norm = k1 * (1.0 - b + b * (dl / avg_dl));
                let score = idf * ((tf * (k1 + 1.0)) / (tf + norm));
                *scores.entry(posting.chunk_hash).or_insert(0.0) += score;
            }
        }
    }

    let mut hits: Vec<SearchHit> = scores
        .into_iter()
        .filter_map(|(chunk_hash, score)| {
            index
                .chunks
                .iter()
                .find(|c| c.chunk_hash == chunk_hash)
                .map(|chunk| SearchHit {
                    chunk_hash,
                    score,
                    text_preview: preview(&chunk.text),
                })
        })
        .collect();

    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    hits.truncate(top_k);
    hits
}

fn vector_search_index(
    index: &SearchIndex,
    query_embedding: &[f32],
    top_k: usize,
) -> Result<Vec<SearchHit>> {
    if top_k == 0 {
        return Ok(Vec::new());
    }
    if query_embedding.is_empty() {
        return Err(anyhow!("query embedding cannot be empty"));
    }

    let query_norm = l2_norm(query_embedding);
    if query_norm == 0.0 {
        return Err(anyhow!("query embedding has zero norm"));
    }

    let mut hits = Vec::new();
    for chunk in &index.chunks {
        let Some(embedding) = &chunk.embedding else {
            continue;
        };
        if embedding.len() != query_embedding.len() {
            continue;
        }

        let emb_norm = l2_norm(embedding);
        if emb_norm == 0.0 {
            continue;
        }

        let dot = query_embedding
            .iter()
            .zip(embedding.iter())
            .map(|(a, b)| a * b)
            .sum::<f32>();
        let score = dot / (query_norm * emb_norm);

        hits.push(SearchHit {
            chunk_hash: chunk.chunk_hash,
            score,
            text_preview: preview(&chunk.text),
        });
    }

    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    hits.truncate(top_k);
    Ok(hits)
}

fn build_semantic_tables(
    chunks: &[IndexChunk],
) -> (
    u32,
    f32,
    BTreeMap<String, u32>,
    BTreeMap<String, u32>,
    BTreeMap<String, Vec<Posting>>,
) {
    let mut doc_len: BTreeMap<String, u32> = BTreeMap::new();
    let mut doc_freq: BTreeMap<String, u32> = BTreeMap::new();
    let mut postings: BTreeMap<String, Vec<Posting>> = BTreeMap::new();

    let mut total_len = 0u32;
    let mut docs = 0u32;

    for chunk in chunks {
        let terms = tokenize(&chunk.text);
        if terms.is_empty() {
            continue;
        }

        docs += 1;
        let mut tf: BTreeMap<String, u32> = BTreeMap::new();
        for term in terms {
            *tf.entry(term).or_insert(0) += 1;
        }

        let len = tf.values().copied().sum::<u32>();
        total_len += len;
        doc_len.insert(chunk.chunk_hash.to_string(), len);

        let mut unique = BTreeSet::new();
        for (term, term_tf) in tf {
            postings.entry(term.clone()).or_default().push(Posting {
                chunk_hash: chunk.chunk_hash,
                tf: term_tf,
            });
            unique.insert(term);
        }

        for term in unique {
            *doc_freq.entry(term).or_insert(0) += 1;
        }
    }

    for plist in postings.values_mut() {
        plist.sort_by(|a, b| a.chunk_hash.cmp(&b.chunk_hash));
    }

    let avg_doc_len = if docs > 0 {
        total_len as f32 / docs as f32
    } else {
        0.0
    };

    (docs, avg_doc_len, doc_len, doc_freq, postings)
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn preview(text: &str) -> String {
    let limit = 96;
    let mut out = text.trim().replace('\n', " ");
    if out.len() > limit {
        out.truncate(limit);
        out.push_str("...");
    }
    out
}

fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::commit::CommitStore;
    use crate::db::Database;
    use crate::manifest::{ChunkManifest, ChunkingSpec, ManifestStore};

    #[test]
    fn semantic_search_returns_relevant_chunk() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let doc_hash = db
            .manifest_store
            .put_doc_manifest_from_bytes(
                &db.blob_store,
                "src".into(),
                b"rust systems programming\npython data scripts",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 24,
                    overlap: 0,
                },
                Some(1),
            )
            .unwrap();

        let empty = db.state_store.empty_root().unwrap();
        let commit = db
            .commit_store
            .create_commit(
                vec![],
                empty,
                vec![doc_hash],
                "agent".into(),
                "index test".into(),
            )
            .unwrap();

        let store = SearchIndexStore::new(db.root.join("index"));
        let _ = store
            .build_for_head(commit, &db.commit_store, &db.manifest_store, &db.blob_store)
            .unwrap();

        let hits = store.semantic_search(commit, "systems rust", 3).unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn vector_search_uses_chunk_embeddings() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let text_hash = db.blob_store.put(b"vector chunk text").unwrap();
        let emb_a = db
            .blob_store
            .put(&crate::canonical::to_cbor(&vec![1.0f32, 0.0f32, 0.0f32]).unwrap())
            .unwrap();
        let emb_b = db
            .blob_store
            .put(&crate::canonical::to_cbor(&vec![0.0f32, 1.0f32, 0.0f32]).unwrap())
            .unwrap();

        let chunk_a = ChunkManifest {
            schema_version: 1,
            chunk_text: text_hash,
            start: 0,
            end: 10,
            embedding: Some(emb_a),
        };
        let chunk_b = ChunkManifest {
            schema_version: 1,
            chunk_text: db.blob_store.put(b"other").unwrap(),
            start: 0,
            end: 5,
            embedding: Some(emb_b),
        };

        let a_hash = db.manifest_store.put_manifest(&chunk_a).unwrap();
        let b_hash = db.manifest_store.put_manifest(&chunk_b).unwrap();

        let empty = db.state_store.empty_root().unwrap();
        let commit = db
            .commit_store
            .create_commit(
                vec![],
                empty,
                vec![a_hash, b_hash],
                "agent".into(),
                "vector index".into(),
            )
            .unwrap();

        let store = SearchIndexStore::new(db.root.join("index"));
        let _ = store
            .build_for_head(commit, &db.commit_store, &db.manifest_store, &db.blob_store)
            .unwrap();

        let hits = store.vector_search(commit, &[1.0, 0.0, 0.0], 2).unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].score > 0.99);
    }

    #[test]
    fn parse_embedding_accepts_json_and_cbor() {
        let cbor = crate::canonical::to_cbor(&vec![1.0f32, 2.0f32]).unwrap();
        let json = serde_json::to_vec(&vec![1.0f32, 2.0f32]).unwrap();
        assert_eq!(parse_embedding(&cbor).unwrap(), vec![1.0, 2.0]);
        assert_eq!(parse_embedding(&json).unwrap(), vec![1.0, 2.0]);
    }

    #[test]
    fn parse_embedding_rejects_invalid_bytes() {
        assert!(parse_embedding(b"bad").is_err());
    }

    #[test]
    fn bm25_tokenizer_lowercases_and_splits() {
        let tokens = tokenize("Rust, systems-programming!");
        assert_eq!(tokens, vec!["rust", "systems", "programming"]);
    }

    #[test]
    fn preview_truncates_long_text() {
        let s = "a".repeat(200);
        let p = preview(&s);
        assert!(p.len() < s.len());
        assert!(p.ends_with("..."));
    }

    #[test]
    fn build_index_without_manifests_is_empty() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let empty = db.state_store.empty_root().unwrap();
        let commit = db
            .commit_store
            .create_commit(vec![], empty, vec![], "agent".into(), "empty".into())
            .unwrap();

        let store = SearchIndexStore::new(db.root.join("index"));
        store
            .build_for_head(commit, &db.commit_store, &db.manifest_store, &db.blob_store)
            .unwrap();
        let index = store.read_index(commit).unwrap();
        assert!(index.chunks.is_empty());
    }

    #[test]
    fn trait_build_returns_error_without_context() {
        let tmp = TempDir::new().unwrap();
        let store = SearchIndexStore::new(tmp.path());
        let h = hash_typed(b"x", b"y");
        let err = IndexBuilder::build(&store, h).unwrap_err();
        assert!(err.to_string().contains("requires stores"));
    }

    #[test]
    fn helper_types_compile_usage() {
        fn _use_types(_: &ManifestStore, _: &CommitStore) {}
    }
}
