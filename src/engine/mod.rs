//! Resident retrieval engine over the canonical store.
//!
//! Layout: `index/segments/<hash>` immutable IndexSegment (CBOR, encrypted
//! if the DB is), `index/heads/<commit>` lists the segments serving that
//! commit. Index for a commit = manifests of its first-parent chain; each
//! commit adds a delta segment, chains past MERGE_THRESHOLD get merged.
//! All derived data: deleting `index/` loses nothing canonical.
//! Hits carry (commit, chunk_hash) -> upgradeable via retrieval_proof.

pub mod segment;
pub mod vector;
pub mod writer;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::canonical::{from_cbor, to_cbor};
use crate::clock::now_unix;
use crate::commit::CommitHash;
use crate::db::Database;
use crate::encryption::EncryptionRuntime;
use crate::hash::{Hash, hash_typed};
use crate::manifest::{QueryHit, QueryManifest};

pub use segment::{ChunkInput, IndexSegment, SearchFilter, SegmentHit};
pub use writer::WriteCoalescer;

const SEGMENT_TAG: &[u8] = b"index_segment:";
const HEAD_SCHEMA_VERSION: u32 = 1;

/// Merge a head's segment chain into one segment past this length.
const MERGE_THRESHOLD: usize = 8;

/// Cap on ancestry walks when looking for an indexed ancestor.
const MAX_CHAIN_WALK: usize = 10_000;

/// RRF constant (standard value from the literature).
const RRF_K: f32 = 60.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentSetManifest {
    schema_version: u32,
    commit: CommitHash,
    /// Oldest → newest. Newest wins on chunk-hash collisions.
    segments: Vec<Hash>,
    built_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineHit {
    pub chunk_hash: Hash,
    pub score: f32,
    pub text_preview: String,
    pub commit: CommitHash,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub segments: usize,
    pub chunks: usize,
    pub chunks_with_embeddings: usize,
    pub unique_terms: usize,
    pub vector_dim: Option<usize>,
    pub hnsw_segments: usize,
}

/// Share behind `Arc`; caches are interior-mutable, reads take RwLock read locks.
pub struct Engine {
    db: Database,
    index_root: PathBuf,
    encryption: Option<Arc<EncryptionRuntime>>,
    segments: RwLock<HashMap<Hash, Arc<IndexSegment>>>,
    heads: RwLock<HashMap<CommitHash, Arc<Vec<Hash>>>>,
    /// Serializes erasure's segment-file deletion against segment reads:
    /// readers take it shared, `reindex_all_heads` takes it exclusive.
    index_gate: RwLock<()>,
}

impl Engine {
    pub fn new(db: Database) -> Self {
        let index_root = db.root.join("index");
        let encryption = db.encryption_runtime();
        Self {
            db,
            index_root,
            encryption,
            segments: RwLock::new(HashMap::new()),
            heads: RwLock::new(HashMap::new()),
            index_gate: RwLock::new(()),
        }
    }

    /// Open a database and wrap it in a resident engine.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self::new(Database::open(path)?))
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Resolve `"main"`-style head names or 64-hex commit hashes to a commit.
    pub fn resolve_commit(&self, head_or_commit: &str) -> Result<CommitHash> {
        if head_or_commit.len() == 64
            && let Ok(hash) = head_or_commit.parse::<Hash>()
        {
            return Ok(hash);
        }
        self.db
            .refs
            .head_get(head_or_commit)?
            .ok_or_else(|| anyhow!("head '{head_or_commit}' has no commits"))
    }

    /// Create a commit and index it eagerly.
    pub fn commit(
        &self,
        head: &str,
        author: &str,
        message: &str,
        manifests: Vec<Hash>,
    ) -> Result<CommitHash> {
        let commit = self
            .db
            .create_commit_at_head(head, author, message, manifests)?;
        self.ensure_indexed(commit)?;
        Ok(commit)
    }

    /// Chunk a document, store blobs + manifest, commit, index. Returns
    /// `(manifest_hash, commit_hash)`.
    pub fn put_document(
        &self,
        head: &str,
        source: &str,
        bytes: &[u8],
        chunking: crate::manifest::ChunkingSpec,
        metadata: Option<crate::manifest::ChunkMetadata>,
        author: &str,
    ) -> Result<(Hash, CommitHash)> {
        let manifest = self
            .db
            .manifest_store
            .put_doc_manifest_from_bytes_with_metadata(
                &self.db.blob_store,
                source.to_string(),
                bytes,
                chunking,
                None,
                metadata,
            )?;
        let commit = self.commit(head, author, &format!("ingest {source}"), vec![manifest])?;
        Ok((manifest, commit))
    }

    /// Group-commit writer for `head`: single-op writes coalesce into shared
    /// batches (one segment + one ref CAS per batch).
    pub fn coalescing_writer(&self, head: &str) -> writer::WriteCoalescer {
        writer::WriteCoalescer::new(
            self.db.clone(),
            head,
            writer::DEFAULT_MAX_BATCH,
            writer::DEFAULT_WINDOW,
        )
    }

    /// Prefetch pass: make the head's index segments and state objects
    /// cache-resident so first queries hit warm paths.
    pub fn warm(&self, head: &str) -> Result<()> {
        let commit = self.resolve_commit(head)?;
        let _ = self.segment_set(commit)?;
        let root = self.db.resolve_state_root(head)?;
        let _ = self.db.state_store.scan_prefix(root, b"")?;
        Ok(())
    }

    pub fn sessions(&self) -> crate::session::SessionStore<'_> {
        crate::session::SessionStore::new(&self.db)
    }

    pub fn checkpoints(&self) -> crate::checkpoint::CheckpointStore<'_> {
        crate::checkpoint::CheckpointStore::new(&self.db)
    }

    /// Upgrade a search hit to an offline-verifiable proof bundle.
    pub fn prove(
        &self,
        commit: CommitHash,
        chunk: Hash,
        include_content: bool,
    ) -> Result<crate::retrieval_proof::ChunkProof> {
        crate::retrieval_proof::prove_chunk(&self.db, commit, chunk, include_content)
    }

    // ---------- persistence ----------

    fn segment_path(&self, hash: Hash) -> PathBuf {
        self.index_root.join("segments").join(hash.to_string())
    }

    fn head_path(&self, commit: CommitHash) -> PathBuf {
        self.index_root.join("heads").join(commit.to_string())
    }

    fn encode(&self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        match &self.encryption {
            Some(rt) => rt.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn decode(&self, raw: Vec<u8>) -> Result<Vec<u8>> {
        match &self.encryption {
            Some(rt) => rt.decrypt(&raw),
            None => Ok(raw),
        }
    }

    fn write_segment(&self, seg: IndexSegment) -> Result<Hash> {
        let bytes = to_cbor(&seg)?;
        let hash = hash_typed(SEGMENT_TAG, &bytes);
        let path = self.segment_path(hash);
        if !path.exists() {
            fs::create_dir_all(path.parent().expect("segments dir"))?;
            crate::atomic::write_atomic(&path, &self.encode(bytes)?)?;
        }
        self.segments
            .write()
            .expect("segment cache poisoned")
            .insert(hash, Arc::new(seg));
        Ok(hash)
    }

    fn load_segment(&self, hash: Hash) -> Result<Arc<IndexSegment>> {
        if let Some(seg) = self
            .segments
            .read()
            .expect("segment cache poisoned")
            .get(&hash)
        {
            return Ok(Arc::clone(seg));
        }
        let path = self.segment_path(hash);
        let raw = fs::read(&path)
            .with_context(|| format!("missing index segment {} at {}", hash, path.display()))?;
        let bytes = self.decode(raw)?;
        if hash_typed(SEGMENT_TAG, &bytes) != hash {
            return Err(anyhow!("index segment {} failed integrity check", hash));
        }
        let seg: Arc<IndexSegment> = Arc::new(from_cbor(&bytes)?);
        self.segments
            .write()
            .expect("segment cache poisoned")
            .insert(hash, Arc::clone(&seg));
        Ok(seg)
    }

    fn read_head(&self, commit: CommitHash) -> Result<Option<Arc<Vec<Hash>>>> {
        if let Some(set) = self.heads.read().expect("head cache poisoned").get(&commit) {
            return Ok(Some(Arc::clone(set)));
        }
        let path = self.head_path(commit);
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let manifest: SegmentSetManifest = from_cbor(&self.decode(raw)?)?;
        if manifest.schema_version != HEAD_SCHEMA_VERSION {
            return Ok(None); // stale derived data; rebuild
        }
        let set = Arc::new(manifest.segments);
        self.heads
            .write()
            .expect("head cache poisoned")
            .insert(commit, Arc::clone(&set));
        Ok(Some(set))
    }

    fn write_head(&self, commit: CommitHash, segments: Vec<Hash>) -> Result<()> {
        let manifest = SegmentSetManifest {
            schema_version: HEAD_SCHEMA_VERSION,
            commit,
            segments: segments.clone(),
            built_at: now_unix()?,
        };
        let path = self.head_path(commit);
        fs::create_dir_all(path.parent().expect("heads dir"))?;
        crate::atomic::write_atomic(&path, &self.encode(to_cbor(&manifest)?)?)?;
        self.heads
            .write()
            .expect("head cache poisoned")
            .insert(commit, Arc::new(segments));
        Ok(())
    }

    // ---------- build ----------

    /// Build delta segments for any unindexed suffix of the first-parent chain.
    pub fn ensure_indexed(&self, commit: CommitHash) -> Result<()> {
        if self.read_head(commit)?.is_some() {
            return Ok(());
        }

        // Walk first parents until an indexed ancestor (or a root).
        let mut chain = vec![commit]; // newest first
        let mut base_segments: Vec<Hash> = Vec::new();
        let mut cursor = commit;
        for _ in 0..MAX_CHAIN_WALK {
            let c = self.db.commit_store.get_commit(cursor)?;
            let Some(&parent) = c.parents.first() else {
                break;
            };
            if let Some(set) = self.read_head(parent)? {
                base_segments = set.as_ref().clone();
                break;
            }
            chain.push(parent);
            cursor = parent;
        }

        // Manifests already covered by the base segments.
        let mut indexed: HashSet<Hash> = HashSet::new();
        for &seg_hash in &base_segments {
            indexed.extend(self.load_segment(seg_hash)?.built_from.iter().copied());
        }

        // Build oldest → newest.
        let mut segments = base_segments;
        for &c_hash in chain.iter().rev() {
            let c = self.db.commit_store.get_commit(c_hash)?;
            let new_manifests: Vec<Hash> = c
                .manifests
                .iter()
                .copied()
                .filter(|m| !indexed.contains(m))
                .collect();
            if !new_manifests.is_empty() {
                let inputs = self.ingest_manifests(&new_manifests)?;
                indexed.extend(new_manifests.iter().copied());
                let seg = IndexSegment::build(new_manifests, inputs);
                segments.push(self.write_segment(seg)?);
            }
            if segments.len() > MERGE_THRESHOLD {
                segments = vec![self.merge_segments(&segments)?];
            }
            self.write_head(c_hash, segments.clone())?;
        }
        Ok(())
    }

    /// Discard every segment/head and rebuild each head from canonical. Used
    /// after erasure: deleting the old segments removes the only derived copies
    /// of erased chunk text/vectors, and the rebuild skips the shredded blobs.
    pub fn reindex_all_heads(&self) -> Result<()> {
        // Exclusive gate: no reader may be mid-load while we delete segments.
        let _gate = self.index_gate.write().expect("index gate poisoned");
        for sub in ["segments", "heads"] {
            let dir = self.index_root.join(sub);
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
            }
        }
        // Drop cached heads/segments or `ensure_indexed` would early-return on
        // the stale head and keep serving the pre-erasure segments.
        self.heads.write().expect("head cache poisoned").clear();
        self.segments
            .write()
            .expect("segment cache poisoned")
            .clear();
        for (_, tip) in self.db.refs.list_heads()? {
            self.ensure_indexed(tip)?;
        }
        Ok(())
    }

    /// Compact a chain into one segment; newest entry wins per chunk hash.
    fn merge_segments(&self, segment_hashes: &[Hash]) -> Result<Hash> {
        let mut built_from: Vec<Hash> = Vec::new();
        let mut inputs: Vec<ChunkInput> = Vec::new();
        for &h in segment_hashes {
            // Oldest first, so IndexSegment::build's last-wins dedup keeps
            // the newest version of each chunk.
            let seg = self.load_segment(h)?;
            built_from.extend(seg.built_from.iter().copied());
            let mut emb_by_doc: HashMap<u32, Vec<f32>> = HashMap::new();
            for (i, &doc) in seg.vec_docs.iter().enumerate() {
                emb_by_doc.insert(doc, seg.vec_data[i].clone());
            }
            for (doc, chunk) in seg.chunks.iter().enumerate() {
                inputs.push(ChunkInput {
                    chunk_hash: chunk.chunk_hash,
                    text: chunk.text.clone(),
                    embedding: emb_by_doc.remove(&(doc as u32)),
                    meta: chunk.meta.clone(),
                });
            }
        }
        built_from.sort();
        built_from.dedup();
        self.write_segment(IndexSegment::build(built_from, inputs))
    }

    /// Manifests -> chunk inputs. Audit-only kinds (Run, Provenance) are skipped.
    fn ingest_manifests(&self, manifests: &[Hash]) -> Result<Vec<ChunkInput>> {
        let per_manifest =
            crate::par::parallel_map(manifests.to_vec(), |m| self.ingest_one_manifest(m));
        let mut inputs = Vec::new();
        for batch in per_manifest {
            inputs.extend(batch?);
        }
        Ok(inputs)
    }

    /// Read a content blob, returning `None` to skip it when it has been
    /// erased (gone + covered by an erasure record). A genuinely missing blob
    /// (corruption) still errors.
    fn read_unless_erased(&self, hash: Hash) -> Result<Option<Vec<u8>>> {
        match self.db.blob_store.get(hash) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) => {
                if crate::erasure::covers(&self.db.root, hash)? {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn ingest_one_manifest(&self, m: Hash) -> Result<Vec<ChunkInput>> {
        let mut inputs = Vec::new();
        for &m in [m].iter() {
            if let Ok(doc) = self.db.manifest_store.get_doc_manifest(m) {
                let fetched = crate::par::parallel_map(doc.chunks.clone(), |chunk_hash| {
                    self.read_unless_erased(chunk_hash).map(|opt| {
                        opt.map(|bytes| ChunkInput {
                            chunk_hash,
                            text: String::from_utf8_lossy(&bytes).to_string(),
                            embedding: None,
                            meta: doc.metadata.clone(),
                        })
                    })
                });
                for input in fetched {
                    if let Some(ci) = input? {
                        inputs.push(ci);
                    }
                }
                continue;
            }
            if let Ok(chunk) = self.db.manifest_store.get_chunk_manifest(m) {
                let Some(bytes) = self.read_unless_erased(chunk.chunk_text)? else {
                    continue;
                };
                let embedding = match chunk.embedding {
                    Some(h) => self
                        .read_unless_erased(h)?
                        .map(|b| parse_embedding(&b))
                        .transpose()?,
                    None => None,
                };
                inputs.push(ChunkInput {
                    chunk_hash: chunk.chunk_text,
                    text: String::from_utf8_lossy(&bytes).to_string(),
                    embedding,
                    meta: chunk.metadata.clone(),
                });
                continue;
            }
            if let Ok(summary) = self.db.manifest_store.get_summary_manifest(m) {
                let Some(bytes) = self.read_unless_erased(summary.summary_text)? else {
                    continue;
                };
                let embedding = match summary.embedding {
                    Some(h) => self
                        .read_unless_erased(h)?
                        .map(|b| parse_embedding(&b))
                        .transpose()?,
                    None => None,
                };
                inputs.push(ChunkInput {
                    chunk_hash: summary.summary_text,
                    text: String::from_utf8_lossy(&bytes).to_string(),
                    embedding,
                    meta: summary.metadata.clone(),
                });
                continue;
            }
        }
        Ok(inputs)
    }

    // ---------- query ----------

    fn segment_set(&self, commit: CommitHash) -> Result<Vec<Arc<IndexSegment>>> {
        // Shared gate: block erasure's segment-file deletion until every segment
        // is loaded into an Arc; past this point the search is memory-only.
        let _gate = self.index_gate.read().expect("index gate poisoned");
        self.ensure_indexed(commit)?;
        let set = self
            .read_head(commit)?
            .ok_or_else(|| anyhow!("index build for {} produced no head manifest", commit))?;
        set.iter().map(|&h| self.load_segment(h)).collect()
    }

    /// Merge per-segment results: newest segment wins per chunk, then sort.
    fn merge_hits(
        commit: CommitHash,
        per_segment: Vec<(Arc<IndexSegment>, Vec<SegmentHit>)>,
        top_k: usize,
    ) -> Vec<EngineHit> {
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut out: Vec<EngineHit> = Vec::new();
        // Newest segment first: freshest chunk version wins.
        for (seg, hits) in per_segment.iter().rev() {
            for hit in hits {
                if !seen.insert(hit.chunk_hash) {
                    continue;
                }
                out.push(EngineHit {
                    chunk_hash: hit.chunk_hash,
                    score: hit.score,
                    text_preview: preview(seg.text_of(hit.doc)),
                    commit,
                });
            }
        }
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(top_k);
        out
    }

    pub fn search_semantic(
        &self,
        commit: CommitHash,
        query: &str,
        top_k: usize,
        filter: &SearchFilter,
    ) -> Result<Vec<EngineHit>> {
        let segments = self.segment_set(commit)?;
        let fetch = top_k.saturating_mul(2).max(top_k);
        let per_segment = segments
            .into_iter()
            .map(|seg| {
                let hits = seg.bm25(query, fetch, filter);
                (seg, hits)
            })
            .collect();
        Ok(Self::merge_hits(commit, per_segment, top_k))
    }

    pub fn search_vector(
        &self,
        commit: CommitHash,
        embedding: &[f32],
        top_k: usize,
        filter: &SearchFilter,
    ) -> Result<Vec<EngineHit>> {
        let segments = self.segment_set(commit)?;
        let fetch = top_k.saturating_mul(2).max(top_k);
        let per_segment = segments
            .into_iter()
            .map(|seg| {
                let hits = seg.vector(embedding, fetch, filter);
                (seg, hits)
            })
            .collect();
        Ok(Self::merge_hits(commit, per_segment, top_k))
    }

    /// BM25 + vector fused with RRF; degrades to one modality if only one given.
    pub fn search_hybrid(
        &self,
        commit: CommitHash,
        query: Option<&str>,
        embedding: Option<&[f32]>,
        top_k: usize,
        filter: &SearchFilter,
    ) -> Result<Vec<EngineHit>> {
        if query.is_none() && embedding.is_none() {
            return Err(anyhow!(
                "hybrid search needs a query, an embedding, or both"
            ));
        }
        let fetch = top_k.saturating_mul(4).max(top_k);
        // Index once, then run both modalities concurrently: reads over
        // immutable segments, so hybrid pays max(bm25, vector) not the sum.
        // Scoped so the read gate releases before the per-modality segment_set
        // calls re-acquire it (a held read lock would block their threads).
        {
            let _gate = self.index_gate.read().expect("index gate poisoned");
            self.ensure_indexed(commit)?;
        }
        let (semantic, vector) = std::thread::scope(|s| {
            let semantic =
                query.map(|q| s.spawn(move || self.search_semantic(commit, q, fetch, filter)));
            let vector =
                embedding.map(|e| s.spawn(move || self.search_vector(commit, e, fetch, filter)));
            (
                semantic.map(|h| h.join().expect("semantic search panicked")),
                vector.map(|h| h.join().expect("vector search panicked")),
            )
        });
        let mut lists: Vec<Vec<EngineHit>> = Vec::new();
        if let Some(hits) = semantic {
            lists.push(hits?);
        }
        if let Some(hits) = vector {
            lists.push(hits?);
        }

        let mut fused: HashMap<Hash, EngineHit> = HashMap::new();
        for list in &lists {
            for (rank, hit) in list.iter().enumerate() {
                let rrf = 1.0 / (RRF_K + rank as f32 + 1.0);
                fused
                    .entry(hit.chunk_hash)
                    .and_modify(|h| h.score += rrf)
                    .or_insert_with(|| EngineHit {
                        score: rrf,
                        ..hit.clone()
                    });
            }
        }
        let mut out: Vec<EngineHit> = fused.into_values().collect();
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(top_k);
        Ok(out)
    }

    /// Stats over the segment set serving `commit`.
    pub fn index_stats(&self, commit: CommitHash) -> Result<IndexStats> {
        let segments = self.segment_set(commit)?;
        let mut stats = IndexStats {
            segments: segments.len(),
            ..IndexStats::default()
        };
        let mut terms: HashSet<&str> = HashSet::new();
        for seg in &segments {
            stats.chunks += seg.chunks.len();
            stats.chunks_with_embeddings += seg.vec_docs.len();
            stats.vector_dim = stats.vector_dim.or(seg.vector_dim);
            if seg.hnsw.is_some() {
                stats.hnsw_segments += 1;
            }
            terms.extend(seg.lexicon.keys().map(String::as_str));
        }
        stats.unique_terms = terms.len();
        Ok(stats)
    }

    // ---------- audit ----------

    /// Write a QueryManifest audit record. Attach to a commit to protect from GC.
    #[allow(clippy::too_many_arguments)]
    pub fn record_query(
        &self,
        commit: CommitHash,
        mode: &str,
        query_text: Option<&str>,
        embedding: Option<&[f32]>,
        top_k: usize,
        filter: &SearchFilter,
        principal: Option<&str>,
        hits: &[EngineHit],
    ) -> Result<Hash> {
        let query_text = match query_text {
            Some(q) => Some(self.db.blob_store.put(q.as_bytes())?),
            None => None,
        };
        let query_embedding = match embedding {
            Some(e) => Some(self.db.blob_store.put(&to_cbor(&e.to_vec())?)?),
            None => None,
        };
        let filters = if *filter == SearchFilter::default() {
            None
        } else {
            Some(serde_json::to_string(filter)?)
        };
        let manifest = QueryManifest {
            schema_version: crate::manifest::MANIFEST_SCHEMA_VERSION,
            commit,
            mode: mode.to_string(),
            query_text,
            query_embedding,
            top_k: top_k as u32,
            filters,
            principal: principal.map(str::to_string),
            executed_at: now_unix()?,
            hits: hits
                .iter()
                .map(|h| QueryHit {
                    chunk: h.chunk_hash,
                    score_micro: (h.score as f64 * 1_000_000.0).round() as i64,
                })
                .collect(),
        };
        self.db.manifest_store.put_manifest(&manifest)
    }
}

/// Decode an embedding blob: canonical CBOR `Vec<f32>`/`Vec<f64>` or a JSON
/// float array.
pub fn parse_embedding(bytes: &[u8]) -> Result<Vec<f32>> {
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
        "embedding bytes are not supported (expected CBOR/JSON float array)"
    ))
}

fn preview(text: &str) -> String {
    let limit = 96;
    let mut out = text.trim().replace('\n', " ");
    if out.len() > limit {
        let mut cut = limit;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::{ChunkManifest, ChunkMetadata, ChunkingSpec};

    fn test_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        (tmp, db)
    }

    fn commit_doc(db: &Database, head: &str, text: &[u8], meta: Option<ChunkMetadata>) -> Hash {
        let doc = db
            .manifest_store
            .put_doc_manifest_from_bytes_with_metadata(
                &db.blob_store,
                "src".into(),
                text,
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 64,
                    overlap: 0,
                },
                Some(1),
                meta,
            )
            .unwrap();
        db.create_commit_at_head(head, "agent", "ingest", vec![doc])
            .unwrap()
    }

    #[test]
    fn semantic_search_through_engine() {
        let (_tmp, db) = test_db();
        let commit = commit_doc(&db, "main", b"rust systems programming here", None);
        let engine = Engine::new(db);
        let hits = engine
            .search_semantic(commit, "rust systems", 5, &SearchFilter::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].score > 0.0);
        assert_eq!(hits[0].commit, commit);
    }

    #[test]
    fn index_accumulates_across_commits() {
        let (_tmp, db) = test_db();
        let _c1 = commit_doc(&db, "main", b"alpha document about rust", None);
        let c2 = commit_doc(&db, "main", b"beta document about python", None);
        let engine = Engine::new(db);

        // Both commits' knowledge is visible at c2.
        let rust = engine
            .search_semantic(c2, "rust", 5, &SearchFilter::default())
            .unwrap();
        let python = engine
            .search_semantic(c2, "python", 5, &SearchFilter::default())
            .unwrap();
        assert!(!rust.is_empty(), "ancestor commit's chunks must be indexed");
        assert!(!python.is_empty());
    }

    #[test]
    fn time_travel_excludes_future_knowledge() {
        let (_tmp, db) = test_db();
        let c1 = commit_doc(&db, "main", b"alpha document about rust", None);
        let _c2 = commit_doc(&db, "main", b"beta document about python", None);
        let engine = Engine::new(db);

        let at_c1 = engine
            .search_semantic(c1, "python", 5, &SearchFilter::default())
            .unwrap();
        assert!(
            at_c1.is_empty(),
            "querying an old commit must not see newer chunks"
        );
    }

    #[test]
    fn merge_compacts_long_chains() {
        let (_tmp, db) = test_db();
        let mut last = Hash::zero();
        for i in 0..(MERGE_THRESHOLD + 3) {
            let text = format!("document number {i} with shared corpus terms");
            last = commit_doc(&db, "main", text.as_bytes(), None);
        }
        let engine = Engine::new(db);
        engine.ensure_indexed(last).unwrap();
        let set = engine.read_head(last).unwrap().unwrap();
        assert!(
            set.len() <= MERGE_THRESHOLD,
            "chain of {} segments was never merged",
            set.len()
        );
        // All knowledge survives the merge.
        let hits = engine
            .search_semantic(last, "document number 0", 20, &SearchFilter::default())
            .unwrap();
        assert!(!hits.is_empty());
    }

    #[test]
    fn vector_and_hybrid_search() {
        let (_tmp, db) = test_db();
        let text_a = db.blob_store.put(b"vector chunk alpha").unwrap();
        let text_b = db.blob_store.put(b"vector chunk beta").unwrap();
        let emb_a = db
            .blob_store
            .put(&to_cbor(&vec![1.0f32, 0.0, 0.0]).unwrap())
            .unwrap();
        let emb_b = db
            .blob_store
            .put(&to_cbor(&vec![0.0f32, 1.0, 0.0]).unwrap())
            .unwrap();
        let m_a = db
            .manifest_store
            .put_manifest(&ChunkManifest {
                schema_version: 3,
                chunk_text: text_a,
                start: 0,
                end: 18,
                embedding: Some(emb_a),
                metadata: None,
            })
            .unwrap();
        let m_b = db
            .manifest_store
            .put_manifest(&ChunkManifest {
                schema_version: 3,
                chunk_text: text_b,
                start: 0,
                end: 17,
                embedding: Some(emb_b),
                metadata: None,
            })
            .unwrap();
        let commit = db
            .create_commit_at_head("main", "agent", "vectors", vec![m_a, m_b])
            .unwrap();

        let engine = Engine::new(db);
        let vec_hits = engine
            .search_vector(commit, &[1.0, 0.1, 0.0], 2, &SearchFilter::default())
            .unwrap();
        assert_eq!(vec_hits[0].chunk_hash, text_a);
        assert!(vec_hits[0].score > 0.9);

        let hybrid = engine
            .search_hybrid(
                commit,
                Some("alpha"),
                Some(&[1.0, 0.0, 0.0]),
                2,
                &SearchFilter::default(),
            )
            .unwrap();
        assert_eq!(hybrid[0].chunk_hash, text_a, "RRF must rank alpha first");
    }

    #[test]
    fn tenant_filter_applies_through_engine() {
        let (_tmp, db) = test_db();
        let meta = ChunkMetadata {
            tenant: Some("acme".into()),
            ..Default::default()
        };
        let _c1 = commit_doc(&db, "main", b"acme private knowledge", Some(meta));
        let c2 = commit_doc(&db, "main", b"public shared knowledge", None);
        let engine = Engine::new(db);

        let acme = SearchFilter {
            tenant: Some("acme".into()),
            ..Default::default()
        };
        let hits = engine.search_semantic(c2, "knowledge", 10, &acme).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].text_preview.contains("acme"));
    }

    #[test]
    fn warm_query_uses_cache_not_disk() {
        let (_tmp, db) = test_db();
        let commit = commit_doc(&db, "main", b"cached corpus text", None);
        let engine = Engine::new(db);
        let _ = engine
            .search_semantic(commit, "cached", 5, &SearchFilter::default())
            .unwrap();

        // Nuke the on-disk index; the warm engine must still answer.
        fs::remove_dir_all(engine.index_root.join("segments")).unwrap();
        fs::remove_dir_all(engine.index_root.join("heads")).unwrap();
        let hits = engine
            .search_semantic(commit, "cached", 5, &SearchFilter::default())
            .unwrap();
        assert!(!hits.is_empty(), "warm query must be served from memory");
    }

    #[test]
    fn query_audit_record_roundtrips() {
        let (_tmp, db) = test_db();
        let commit = commit_doc(&db, "main", b"auditable content", None);
        let engine = Engine::new(db);
        let hits = engine
            .search_semantic(commit, "auditable", 5, &SearchFilter::default())
            .unwrap();
        let h = engine
            .record_query(
                commit,
                "semantic",
                Some("auditable"),
                None,
                5,
                &SearchFilter::default(),
                Some("key:test"),
                &hits,
            )
            .unwrap();
        let manifest = engine.db().manifest_store.get_query_manifest(h).unwrap();
        assert_eq!(manifest.commit, commit);
        assert_eq!(manifest.hits.len(), hits.len());
        assert_eq!(manifest.principal.as_deref(), Some("key:test"));
    }
}
