//! Immutable index segments: BM25 postings + metadata + vectors for the
//! chunks of a manifest set. Derived data — rebuildable, never part of any
//! commit identity, layout free to change.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::manifest::ChunkMetadata;

use super::vector::{
    EF_SEARCH, HnswGraph, dot, dot_q, exact_search, exact_search_over, normalize, quantize,
};

pub const SEGMENT_SCHEMA_VERSION: u32 = 2;

/// Below this many vectors, exact scan beats the graph.
const HNSW_BUILD_THRESHOLD: usize = 256;

/// Filters narrower than this skip the graph entirely.
const EXACT_SCAN_LIMIT: usize = 1024;

/// Minimum visible fraction of a segment for graph traversal to be worth it.
///
/// The beam admits a node when its distance beats the worst *matching* result,
/// so under a selective filter that radius is set by the ef-th nearest visible
/// vector and is wide enough to admit most of the segment. Traversal then
/// degenerates to a near-full scan that is slower than the exact path and whose
/// cost scales with rows the caller cannot see. Measured at 1200 visible of
/// 21200: graph 4.3 ms vs exact 0.2 ms.
const GRAPH_MIN_VISIBLE_FRACTION: usize = 2; // i.e. >= 1/2 of the segment

/// SQ8 traversal pays off when dot products are memory-bound; below this
/// dimensionality f32 traversal is faster than quantize+rerank overhead.
const SQ8_MIN_DIM: usize = 256;

const BM25_K1: f32 = 1.5;
const BM25_B: f32 = 0.75;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentChunk {
    pub chunk_hash: Hash,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<ChunkMetadata>,
}

/// Per-term postings: ascending doc ids + aligned term frequencies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostingList {
    pub docs: Vec<u32>,
    pub tfs: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexSegment {
    pub schema_version: u32,
    /// Manifest hashes whose chunks this segment indexes.
    pub built_from: Vec<Hash>,
    /// Doc id = position in this vector.
    pub chunks: Vec<SegmentChunk>,
    pub doc_len: Vec<u32>,
    pub total_len: u64,
    pub lexicon: BTreeMap<String, PostingList>,
    pub vector_dim: Option<usize>,
    /// Doc ids that carry embeddings, ascending; aligned with `vec_data`.
    pub vec_docs: Vec<u32>,
    /// L2-normalized embeddings (exact path + rerank).
    pub vec_data: Vec<Vec<f32>>,
    /// SQ8 codes (i8 as u8 bit-patterns), aligned with `vec_data`; HNSW
    /// traversal runs on these — ~4x dot throughput, 4x less memory touched.
    #[serde(default)]
    pub vec_q: Vec<Vec<u8>>,
    /// Per-vector SQ8 scales, aligned with `vec_q`.
    #[serde(default)]
    pub vec_scale: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hnsw: Option<HnswGraph>,
    /// Any chunk carries an ACL; gates the no-filter fast path.
    #[serde(default)]
    pub any_acl: bool,
    /// Tenant to its doc ids, ascending. Lets a tenant-scoped query cost its
    /// own partition instead of the whole segment, which is both the dominant
    /// residual leak and, for a small tenant in a large database, most of its
    /// query latency. Empty means no index: callers fall back to a full scan,
    /// which is what old segments and untenanted corpora get.
    #[serde(default)]
    pub tenants: BTreeMap<String, Vec<u32>>,
}

/// Retrieval filter over [`ChunkMetadata`]; conditions AND together.
/// tenant/doc_type/language: exact match, absent field = no match.
/// acl: empty chunk ACL = public, else needs an overlapping tag.
/// at: valid_from <= at < valid_to and at < expires_at; None = no temporal
/// filtering (replay semantics).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SearchFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acl: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

impl SearchFilter {
    /// No restricting condition set. Caller ACL tags only grant access, so
    /// they don't count; ACL enforcement itself is never skippable.
    pub fn is_unrestricted(&self) -> bool {
        self.tenant.is_none()
            && self.doc_type.is_none()
            && self.language.is_none()
            && self.at.is_none()
    }

    pub fn matches(&self, meta: Option<&ChunkMetadata>) -> bool {
        let default_meta = ChunkMetadata::default();
        let m = meta.unwrap_or(&default_meta);

        if let Some(t) = &self.tenant
            && m.tenant.as_deref() != Some(t.as_str())
        {
            return false;
        }
        if let Some(dt) = &self.doc_type
            && m.doc_type.as_deref() != Some(dt.as_str())
        {
            return false;
        }
        if let Some(lang) = &self.language
            && m.language.as_deref() != Some(lang.as_str())
        {
            return false;
        }
        // Empty chunk ACL = public; otherwise the caller needs an overlap.
        if !m.acl.is_empty() && !m.acl.iter().any(|tag| self.acl.contains(tag)) {
            return false;
        }
        if let Some(at) = self.at {
            if let Some(from) = m.valid_from
                && at < from
            {
                return false;
            }
            if let Some(to) = m.valid_to
                && at >= to
            {
                return false;
            }
            if let Some(exp) = m.expires_at
                && at >= exp
            {
                return false;
            }
        }
        true
    }
}

/// Ingestion input for [`IndexSegment::build`].
#[derive(Debug, Clone)]
pub struct ChunkInput {
    pub chunk_hash: Hash,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
    pub meta: Option<ChunkMetadata>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SegmentHit {
    pub chunk_hash: Hash,
    pub score: f32,
    pub doc: u32,
}

impl IndexSegment {
    /// Build from chunks; later duplicates of a chunk_hash win.
    pub fn build(built_from: Vec<Hash>, inputs: Vec<ChunkInput>) -> Self {
        // Dedup by chunk hash, last occurrence wins, stable order otherwise.
        let mut order: Vec<Hash> = Vec::new();
        let mut by_hash: BTreeMap<Hash, ChunkInput> = BTreeMap::new();
        for input in inputs {
            if !by_hash.contains_key(&input.chunk_hash) {
                order.push(input.chunk_hash);
            }
            by_hash.insert(input.chunk_hash, input);
        }

        let mut chunks = Vec::with_capacity(order.len());
        let mut doc_len = Vec::with_capacity(order.len());
        let mut total_len = 0u64;
        let mut lexicon: BTreeMap<String, PostingList> = BTreeMap::new();
        let mut vector_dim: Option<usize> = None;
        let mut vec_docs: Vec<u32> = Vec::new();
        let mut vec_data: Vec<Vec<f32>> = Vec::new();

        for hash in order {
            let input = by_hash.remove(&hash).expect("hash collected above");
            let doc = chunks.len() as u32;

            // Lexical tables.
            let mut tf: BTreeMap<String, u32> = BTreeMap::new();
            for term in tokenize(&input.text) {
                *tf.entry(term).or_insert(0) += 1;
            }
            let len: u32 = tf.values().sum();
            total_len += len as u64;
            doc_len.push(len);
            for (term, term_tf) in tf {
                let entry = lexicon.entry(term).or_insert_with(|| PostingList {
                    docs: Vec::new(),
                    tfs: Vec::new(),
                });
                entry.docs.push(doc);
                entry.tfs.push(term_tf);
            }

            // Vector tables: drop zero-norm and dim-mismatched embeddings.
            if let Some(mut emb) = input.embedding {
                let dim_ok = match vector_dim {
                    Some(d) => emb.len() == d,
                    None => true,
                };
                if dim_ok && normalize(&mut emb) {
                    vector_dim.get_or_insert(emb.len());
                    vec_docs.push(doc);
                    vec_data.push(emb);
                }
            }

            chunks.push(SegmentChunk {
                chunk_hash: input.chunk_hash,
                text: input.text,
                meta: input.meta.filter(|m| !m.is_empty()),
            });
        }

        let (hnsw, vec_q, vec_scale) = if vec_data.len() >= HNSW_BUILD_THRESHOLD {
            let (codes, scales): (Vec<Vec<u8>>, Vec<f32>) =
                vec_data.iter().map(|v| quantize(v)).unzip();
            // High dims: construct over the SQ8 metric too — distance evals
            // dominate build time and move 4x less memory quantized.
            let graph = if vector_dim.unwrap_or(0) >= SQ8_MIN_DIM {
                HnswGraph::build_quantized(&codes, &scales)
            } else {
                HnswGraph::build(&vec_data)
            };
            (graph, codes, scales)
        } else {
            (None, Vec::new(), Vec::new())
        };
        let any_acl = chunks
            .iter()
            .any(|c| c.meta.as_ref().is_some_and(|m| !m.acl.is_empty()));
        let mut tenants: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for (doc, chunk) in chunks.iter().enumerate() {
            if let Some(t) = chunk.meta.as_ref().and_then(|m| m.tenant.as_deref()) {
                tenants.entry(t.to_string()).or_default().push(doc as u32);
            }
        }

        Self {
            schema_version: SEGMENT_SCHEMA_VERSION,
            built_from,
            chunks,
            doc_len,
            total_len,
            lexicon,
            vector_dim,
            vec_docs,
            vec_data,
            vec_q,
            vec_scale,
            hnsw,
            any_acl,
            tenants,
        }
    }

    pub fn avg_doc_len(&self) -> f32 {
        if self.chunks.is_empty() {
            return 1.0;
        }
        (self.total_len as f32 / self.chunks.len() as f32).max(1.0)
    }

    /// Doc ids passing `filter`; `None` = all docs. Fast path only when the
    /// filter is unrestricted AND the segment holds no ACL'd chunks.
    pub fn filter_docs(&self, filter: &SearchFilter) -> Option<Vec<u32>> {
        if filter.is_unrestricted() && !self.any_acl {
            return None;
        }
        // Tenant-scoped: start from the partition rather than scanning every
        // chunk, so cost tracks the caller's own data.
        if let Some(tenant) = &filter.tenant
            && !self.tenants.is_empty()
        {
            let ids = self.tenants.get(tenant).cloned().unwrap_or_default();
            return Some(
                ids.into_iter()
                    .filter(|&d| filter.matches(self.chunks[d as usize].meta.as_ref()))
                    .collect(),
            );
        }
        Some(
            self.chunks
                .iter()
                .enumerate()
                .filter(|(_, c)| filter.matches(c.meta.as_ref()))
                .map(|(i, _)| i as u32)
                .collect(),
        )
    }

    /// BM25 top-k over this segment, restricted to `filter`.
    ///
    /// TAAT MaxScore: terms process in descending upper-bound order; once
    /// the remaining terms cannot lift any unseen doc into the top-k, they
    /// only update already-touched docs. Cost tracks result density, not
    /// posting-list length. Scores accumulate in a dense vec — no per-entry
    /// allocator traffic on the hot path.
    pub fn bm25(&self, query: &str, top_k: usize, filter: &SearchFilter) -> Vec<SegmentHit> {
        if top_k == 0 || self.chunks.is_empty() {
            return Vec::new();
        }
        let terms = tokenize(query);
        if terms.is_empty() {
            return Vec::new();
        }
        let allowed = self.filter_docs(filter);
        let allowed_set: Option<Vec<bool>> = allowed.as_ref().map(|ids| {
            let mut set = vec![false; self.chunks.len()];
            for &id in ids {
                set[id as usize] = true;
            }
            set
        });

        // Scoped to the visible partition: segment-global `N`/`df` let a caller
        // invert its own score to recover another tenant's exact counts.
        let (n_docs, avg_dl) = match &allowed_set {
            None => (self.chunks.len() as f32, self.avg_doc_len()),
            Some(mask) => {
                let mut visible = 0usize;
                let mut total_len = 0u64;
                for (doc, &ok) in mask.iter().enumerate() {
                    if ok {
                        visible += 1;
                        total_len += self.doc_len[doc] as u64;
                    }
                }
                if visible == 0 {
                    return Vec::new();
                }
                (visible as f32, (total_len as f32 / visible as f32).max(1.0))
            }
        };

        // (postings, idf, upper_bound); ub = idf * (k1 + 1) bounds any single
        // term's contribution since tf*(k1+1)/(tf+norm) < k1+1.
        let mut term_data: Vec<(&PostingList, f32, f32)> = terms
            .iter()
            .filter_map(|term| self.lexicon.get(term))
            .filter_map(|postings| {
                let df = match &allowed_set {
                    None => postings.docs.len(),
                    Some(mask) => postings
                        .docs
                        .iter()
                        .filter(|&&doc| mask[doc as usize])
                        .count(),
                };
                // Present only in hidden docs = absent, for this caller.
                if df == 0 {
                    return None;
                }
                let df = df as f32;
                let idf = ((n_docs - df + 0.5) / (df + 0.5) + 1.0).ln();
                Some((postings, idf, idf * (BM25_K1 + 1.0)))
            })
            .collect();
        if term_data.is_empty() {
            return Vec::new();
        }
        term_data.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));
        let mut remaining_ub: f32 = term_data.iter().map(|(_, _, ub)| ub).sum();

        let mut scores = vec![0.0f32; self.chunks.len()];
        let mut touched: Vec<u32> = Vec::new();
        let mut threshold = f32::NEG_INFINITY; // kth-best so far

        for (postings, idf, ub) in term_data {
            // Unseen docs can score at most remaining_ub; below the current
            // kth-best they can never enter the top-k.
            let admit_new = touched.len() < top_k || remaining_ub > threshold;
            remaining_ub -= ub;

            for (i, &doc) in postings.docs.iter().enumerate() {
                let d = doc as usize;
                if let Some(set) = &allowed_set
                    && !set[d]
                {
                    continue;
                }
                let seen = scores[d] > 0.0;
                if !seen && !admit_new {
                    continue;
                }
                let tf = postings.tfs[i] as f32;
                let dl = self.doc_len[d] as f32;
                let norm = BM25_K1 * (1.0 - BM25_B + BM25_B * (dl / avg_dl));
                scores[d] += idf * ((tf * (BM25_K1 + 1.0)) / (tf + norm));
                if !seen {
                    touched.push(doc);
                }
            }

            if touched.len() >= top_k {
                let mut top: Vec<f32> = touched.iter().map(|&d| scores[d as usize]).collect();
                let kth = top.len() - top_k;
                top.select_nth_unstable_by(kth, |a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
                threshold = top[kth];
            }
        }

        let mut hits: Vec<SegmentHit> = touched
            .into_iter()
            .map(|doc| SegmentHit {
                chunk_hash: self.chunks[doc as usize].chunk_hash,
                score: scores[doc as usize],
                doc,
            })
            .collect();
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
        hits.truncate(top_k);
        hits
    }

    /// Vector top-k. Exact scan for small/filtered candidate sets, HNSW with
    /// a traversal predicate otherwise, exact fallback if it under-delivers.
    pub fn vector(&self, query: &[f32], top_k: usize, filter: &SearchFilter) -> Vec<SegmentHit> {
        if top_k == 0 || self.vec_data.is_empty() {
            return Vec::new();
        }
        let Some(dim) = self.vector_dim else {
            return Vec::new();
        };
        if query.len() != dim {
            return Vec::new();
        }
        let mut q = query.to_vec();
        if !normalize(&mut q) {
            return Vec::new();
        }

        let allowed = self.filter_docs(filter);
        // Allowed doc ids to vector-node ids. `vec_docs` is ascending, so this
        // is a binary search per candidate rather than a pass over the segment.
        let allowed_nodes: Option<Vec<u32>> = allowed.as_ref().map(|ids| {
            ids.iter()
                .filter_map(|&doc| self.vec_docs.binary_search(&doc).ok().map(|n| n as u32))
                .collect()
        });
        let candidate_count = match &allowed_nodes {
            Some(nodes) => nodes.len(),
            None => self.vec_data.len(),
        };
        if candidate_count == 0 {
            return Vec::new();
        }

        // Graph only when it can actually prune: a large candidate set *and* a
        // filter that leaves most of the segment visible.
        let graph_pays = candidate_count > EXACT_SCAN_LIMIT
            && candidate_count * GRAPH_MIN_VISIBLE_FRACTION >= self.vec_data.len();

        // The graph needs a predicate over arbitrary nodes, so it pays one pass
        // to build the mask. That is only reached when the filter is
        // unselective, where the pass is a small part of the traversal anyway.
        let mask: Option<Vec<bool>> = if graph_pays {
            allowed_nodes.as_ref().map(|nodes| {
                let mut ok = vec![false; self.vec_data.len()];
                for &n in nodes {
                    ok[n as usize] = true;
                }
                ok
            })
        } else {
            None
        };
        let predicate = mask.as_ref().map(|m| move |node: u32| m[node as usize]);
        let results = match &self.hnsw {
            Some(graph) if graph_pays => {
                let ef = EF_SEARCH.max(top_k * 4);
                let pred_ref: Option<&dyn Fn(u32) -> bool> =
                    predicate.as_ref().map(|p| p as &dyn Fn(u32) -> bool);
                let hits = if self.vec_q.len() == self.vec_data.len() && dim >= SQ8_MIN_DIM {
                    // SQ8 traversal, then f32 rerank of an oversampled set.
                    let (q_codes, q_scale) = quantize(&q);
                    let dist = |node: u32| -> f32 {
                        let i = node as usize;
                        1.0 - dot_q(&q_codes, &self.vec_q[i]) as f32 * q_scale * self.vec_scale[i]
                    };
                    let fetch = (top_k * 4).max(top_k);
                    let mut cands =
                        graph.search_with(&dist, self.vec_data.len(), fetch, ef, pred_ref);
                    for c in cands.iter_mut() {
                        c.0 = dot(&q, &self.vec_data[c.1 as usize]);
                    }
                    cands.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
                    cands.truncate(top_k);
                    cands
                } else {
                    graph.search(&self.vec_data, &q, top_k, ef, pred_ref)
                };
                if hits.len() >= top_k.min(candidate_count) {
                    hits
                } else {
                    // Completeness guard, not a hot path: the graph has never
                    // been observed to under-deliver, including when asked for
                    // every visible node at exactly the selectivity threshold.
                    // It is not *provably* unreachable though (HNSW gives no
                    // connectivity guarantee, and pruning could isolate a node),
                    // and the check costs one comparison against silently
                    // returning a short result set. Kept deliberately.
                    match &allowed_nodes {
                        Some(nodes) => exact_search_over(&self.vec_data, nodes, &q, top_k),
                        None => exact_search(&self.vec_data, &q, top_k, None),
                    }
                }
            }
            _ => match &allowed_nodes {
                Some(nodes) => exact_search_over(&self.vec_data, nodes, &q, top_k),
                None => exact_search(&self.vec_data, &q, top_k, None),
            },
        };

        results
            .into_iter()
            .map(|(score, node)| {
                let doc = self.vec_docs[node as usize];
                SegmentHit {
                    chunk_hash: self.chunks[doc as usize].chunk_hash,
                    score,
                    doc,
                }
            })
            .collect()
    }

    pub fn text_of(&self, doc: u32) -> &str {
        &self.chunks[doc as usize].text
    }
}

pub(crate) fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_typed;

    fn chunk(i: usize, text: &str, meta: Option<ChunkMetadata>) -> ChunkInput {
        ChunkInput {
            chunk_hash: hash_typed(b"test_chunk:", format!("{i}").as_bytes()),
            text: text.to_string(),
            embedding: None,
            meta,
        }
    }

    fn chunk_with_vec(i: usize, text: &str, emb: Vec<f32>) -> ChunkInput {
        ChunkInput {
            embedding: Some(emb),
            ..chunk(i, text, None)
        }
    }

    #[test]
    fn bm25_finds_relevant_chunk() {
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk(0, "rust systems programming", None),
                chunk(1, "python data scripts", None),
            ],
        );
        let hits = seg.bm25("rust systems", 5, &SearchFilter::default());
        assert_eq!(hits[0].doc, 0);
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn duplicate_chunk_hash_last_wins() {
        let mut a = chunk(0, "old text", None);
        let b = ChunkInput {
            chunk_hash: a.chunk_hash,
            text: "new text".into(),
            embedding: None,
            meta: None,
        };
        a.text = "old text".into();
        let seg = IndexSegment::build(vec![], vec![a, b]);
        assert_eq!(seg.chunks.len(), 1);
        assert_eq!(seg.chunks[0].text, "new text");
    }

    #[test]
    fn tenant_filter_excludes_other_and_untagged_chunks() {
        let meta_a = ChunkMetadata {
            tenant: Some("a".into()),
            ..Default::default()
        };
        let meta_b = ChunkMetadata {
            tenant: Some("b".into()),
            ..Default::default()
        };
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk(0, "shared words here", Some(meta_a)),
                chunk(1, "shared words here", Some(meta_b)),
                chunk(2, "shared words here", None),
            ],
        );
        let filter = SearchFilter {
            tenant: Some("a".into()),
            ..Default::default()
        };
        let hits = seg.bm25("shared words", 10, &filter);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].doc, 0);
    }

    #[test]
    fn acl_empty_is_public_nonempty_requires_overlap() {
        let secret = ChunkMetadata {
            acl: vec!["group:hr".into()],
            ..Default::default()
        };
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk(0, "common token", None),
                chunk(1, "common token", Some(secret)),
            ],
        );
        let no_tags = seg.bm25("common", 10, &SearchFilter::default());
        assert_eq!(no_tags.len(), 1);
        assert_eq!(no_tags[0].doc, 0);

        let hr = SearchFilter {
            acl: vec!["group:hr".into()],
            ..Default::default()
        };
        assert_eq!(seg.bm25("common", 10, &hr).len(), 2);
    }

    #[test]
    fn validity_window_and_expiry_respected() {
        let windowed = ChunkMetadata {
            valid_from: Some(100),
            valid_to: Some(200),
            ..Default::default()
        };
        let expiring = ChunkMetadata {
            expires_at: Some(150),
            ..Default::default()
        };
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk(0, "temporal token", Some(windowed)),
                chunk(1, "temporal token", Some(expiring)),
            ],
        );
        let at = |t: u64| SearchFilter {
            at: Some(t),
            ..Default::default()
        };
        assert_eq!(seg.bm25("temporal", 10, &at(50)).len(), 1); // only expiring
        assert_eq!(seg.bm25("temporal", 10, &at(120)).len(), 2);
        assert_eq!(seg.bm25("temporal", 10, &at(170)).len(), 1); // only windowed
        assert_eq!(seg.bm25("temporal", 10, &at(300)).len(), 0);
        // No `at` = no temporal filtering (replay semantics).
        assert_eq!(seg.bm25("temporal", 10, &SearchFilter::default()).len(), 2);
    }

    /// Regression: a tenant's own score must not move when documents it
    /// cannot see are added or removed. Before collection statistics were
    /// partition-scoped, this score was strictly monotone in the hidden
    /// count, letting one tenant read another's per-term document frequency
    /// exactly (BENCHMARKS.md §5).
    #[test]
    fn tenant_scores_are_independent_of_hidden_documents() {
        let mine = ChunkMetadata {
            tenant: Some("attacker".into()),
            ..Default::default()
        };
        let theirs = ChunkMetadata {
            tenant: Some("victim".into()),
            ..Default::default()
        };
        let filter = SearchFilter {
            tenant: Some("attacker".into()),
            ..Default::default()
        };

        let score_with = |victim_docs: usize, victim_has_term: bool| {
            let mut inputs = vec![chunk(0, "secret probe term", Some(mine.clone()))];
            for j in 0..victim_docs {
                let text = if victim_has_term {
                    "secret probe term"
                } else {
                    "unrelated filler words"
                };
                inputs.push(chunk(1000 + j, text, Some(theirs.clone())));
            }
            let seg = IndexSegment::build(vec![], inputs);
            let hits = seg.bm25("probe", 10, &filter);
            assert_eq!(hits.len(), 1, "filter must hide every victim document");
            hits[0].score
        };

        let baseline = score_with(0, true);
        for victim_docs in [1usize, 2, 10, 100, 500] {
            for has_term in [true, false] {
                let observed = score_with(victim_docs, has_term);
                assert_eq!(
                    observed.to_bits(),
                    baseline.to_bits(),
                    "score leaked {victim_docs} hidden docs (term present: {has_term})"
                );
            }
        }
    }

    /// A term occurring only in hidden documents must be indistinguishable
    /// from a term that does not occur at all.
    #[test]
    fn term_only_in_hidden_docs_yields_no_hits() {
        let mine = ChunkMetadata {
            tenant: Some("a".into()),
            ..Default::default()
        };
        let theirs = ChunkMetadata {
            tenant: Some("b".into()),
            ..Default::default()
        };
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk(0, "alpha", Some(mine)),
                chunk(1, "confidential", Some(theirs)),
            ],
        );
        let filter = SearchFilter {
            tenant: Some("a".into()),
            ..Default::default()
        };
        assert!(seg.bm25("confidential", 10, &filter).is_empty());
        assert!(seg.bm25("nonexistentword", 10, &filter).is_empty());
    }

    /// The tenant index must not change *what* a filter returns, only what it
    /// costs. Correctness is checked against the unindexed scan.
    #[test]
    fn tenant_index_matches_full_scan() {
        let meta = |t: &str, lang: Option<&str>| {
            Some(ChunkMetadata {
                tenant: Some(t.into()),
                language: lang.map(str::to_string),
                ..Default::default()
            })
        };
        let mut inputs = vec![
            chunk(0, "alpha shared", meta("a", Some("en"))),
            chunk(1, "alpha shared", meta("a", Some("fr"))),
            chunk(2, "alpha shared", meta("b", Some("en"))),
            chunk(3, "alpha shared", None),
        ];
        for i in 0..50 {
            inputs.push(chunk(100 + i, "alpha shared", meta("b", Some("en"))));
        }
        let seg = IndexSegment::build(vec![], inputs);
        assert_eq!(seg.tenants.len(), 2, "index must cover both tenants");

        // Every filter shape must agree with a scan that ignores the index.
        for filter in [
            SearchFilter {
                tenant: Some("a".into()),
                ..Default::default()
            },
            SearchFilter {
                tenant: Some("a".into()),
                language: Some("en".into()),
                ..Default::default()
            },
            SearchFilter {
                tenant: Some("absent".into()),
                ..Default::default()
            },
            SearchFilter::default(),
        ] {
            let via_index = seg.filter_docs(&filter);
            let via_scan: Option<Vec<u32>> = if filter.is_unrestricted() && !seg.any_acl {
                None
            } else {
                Some(
                    seg.chunks
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| filter.matches(c.meta.as_ref()))
                        .map(|(i, _)| i as u32)
                        .collect(),
                )
            };
            assert_eq!(
                via_index, via_scan,
                "filter {filter:?} diverged from a full scan"
            );
        }

        // An untenanted chunk is not reachable through a tenant filter.
        let a = SearchFilter {
            tenant: Some("a".into()),
            ..Default::default()
        };
        assert!(!seg.filter_docs(&a).unwrap().contains(&3));
    }

    /// A selective filter must not route to the graph. The beam cannot prune
    /// when its radius is set by visible results, so traversal degenerates to a
    /// near-full scan: slower than the exact path, and its cost scales with rows
    /// the caller cannot see.
    #[test]
    fn selective_filter_avoids_degenerate_graph_traversal() {
        const DIM: usize = 32;
        const VISIBLE: usize = 1100;
        let mine = ChunkMetadata {
            tenant: Some("a".into()),
            ..Default::default()
        };
        let theirs = ChunkMetadata {
            tenant: Some("b".into()),
            ..Default::default()
        };
        let mut inputs: Vec<ChunkInput> = (0..VISIBLE)
            .map(|i| {
                let mut v = synthetic(i, DIM);
                super::super::vector::normalize(&mut v);
                ChunkInput {
                    chunk_hash: hash_typed(b"sel:", format!("v{i}").as_bytes()),
                    text: "doc".into(),
                    embedding: Some(v),
                    meta: Some(mine.clone()),
                }
            })
            .collect();
        for j in 0..5000 {
            let mut v = synthetic(100_000 + j, DIM);
            super::super::vector::normalize(&mut v);
            inputs.push(ChunkInput {
                chunk_hash: hash_typed(b"sel:", format!("h{j}").as_bytes()),
                text: "doc".into(),
                embedding: Some(v),
                meta: Some(theirs.clone()),
            });
        }
        let seg = IndexSegment::build(vec![], inputs);
        assert!(seg.hnsw.is_some(), "graph should exist at this size");

        let filter = SearchFilter {
            tenant: Some("a".into()),
            ..Default::default()
        };
        let mut q = synthetic(7, DIM);
        super::super::vector::normalize(&mut q);
        let hits = seg.vector(&q, 10, &filter);
        assert_eq!(hits.len(), 10);

        // Routing to the exact path makes it the oracle, so the filtered result
        // must equal exact search over the visible set.
        let allowed = seg.filter_docs(&filter).unwrap();
        let mut doc_ok = vec![false; seg.chunks.len()];
        for id in &allowed {
            doc_ok[*id as usize] = true;
        }
        let mask: Vec<bool> = seg.vec_docs.iter().map(|&d| doc_ok[d as usize]).collect();
        let pred = |n: u32| mask[n as usize];
        let oracle = super::super::vector::exact_search(&seg.vec_data, &q, 10, Some(&pred));
        let oracle_hashes: Vec<Hash> = oracle
            .iter()
            .map(|(_, n)| seg.chunks[seg.vec_docs[*n as usize] as usize].chunk_hash)
            .collect();
        let got: Vec<Hash> = hits.iter().map(|h| h.chunk_hash).collect();
        assert_eq!(
            got, oracle_hashes,
            "selective filter must match exact search"
        );
    }

    fn synthetic(i: usize, dim: usize) -> Vec<f32> {
        (0..dim)
            .map(|j| {
                let mut x = (i * dim + j) as u64;
                x = x.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(31);
                ((x % 2000) as f32 / 1000.0) - 1.0
            })
            .collect()
    }

    #[test]
    fn vector_search_exact_path() {
        let seg = IndexSegment::build(
            vec![],
            vec![
                chunk_with_vec(0, "a", vec![1.0, 0.0, 0.0]),
                chunk_with_vec(1, "b", vec![0.0, 1.0, 0.0]),
            ],
        );
        let hits = seg.vector(&[1.0, 0.1, 0.0], 2, &SearchFilter::default());
        assert_eq!(hits[0].doc, 0);
        assert!(hits[0].score > 0.9);
    }

    #[test]
    fn vector_dim_mismatch_returns_empty() {
        let seg = IndexSegment::build(vec![], vec![chunk_with_vec(0, "a", vec![1.0, 0.0])]);
        assert!(
            seg.vector(&[1.0, 0.0, 0.0], 5, &SearchFilter::default())
                .is_empty()
        );
    }

    #[test]
    fn large_segment_builds_hnsw_and_recall_holds() {
        let inputs: Vec<ChunkInput> = (0..600)
            .map(|i| {
                let mut v: Vec<f32> = (0..16)
                    .map(|j| {
                        let mut x = (i * 16 + j) as u64;
                        x = x.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(31);
                        ((x % 2000) as f32 / 1000.0) - 1.0
                    })
                    .collect();
                super::super::vector::normalize(&mut v);
                chunk_with_vec(i, "filler", v)
            })
            .collect();
        let queries: Vec<Vec<f32>> = inputs[..20]
            .iter()
            .map(|c| c.embedding.clone().unwrap())
            .collect();
        let seg = IndexSegment::build(vec![], inputs);
        assert!(seg.hnsw.is_some(), "expected HNSW above threshold");

        // Self-queries must return the query chunk first.
        for (i, q) in queries.iter().enumerate() {
            let hits = seg.vector(q, 1, &SearchFilter::default());
            assert_eq!(hits[0].doc, i as u32, "self-recall failed for {i}");
        }
    }

    #[test]
    fn high_dim_sq8_recall_holds_vs_exact_oracle() {
        const DIM: usize = 384;
        let inputs: Vec<ChunkInput> = (0..1200)
            .map(|i| {
                let mut v: Vec<f32> = (0..DIM)
                    .map(|j| {
                        let mut x = (i * DIM + j) as u64;
                        x = x.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(31);
                        ((x % 2000) as f32 / 1000.0) - 1.0
                    })
                    .collect();
                super::super::vector::normalize(&mut v);
                chunk_with_vec(i, "filler", v)
            })
            .collect();
        let queries: Vec<Vec<f32>> = inputs
            .iter()
            .step_by(40)
            .take(25)
            .map(|c| c.embedding.clone().unwrap())
            .collect();
        let seg = IndexSegment::build(vec![], inputs);
        assert!(seg.hnsw.is_some());
        assert_eq!(seg.vec_q.len(), seg.vec_data.len());

        let mut overlap = 0usize;
        for q in &queries {
            let exact: std::collections::HashSet<Hash> =
                super::super::vector::exact_search(&seg.vec_data, q, 10, None)
                    .into_iter()
                    .map(|(_, node)| seg.chunks[seg.vec_docs[node as usize] as usize].chunk_hash)
                    .collect();
            let approx = seg.vector(q, 10, &SearchFilter::default());
            overlap += approx
                .iter()
                .filter(|h| exact.contains(&h.chunk_hash))
                .count();
        }
        let recall = overlap as f32 / (queries.len() * 10) as f32;
        assert!(
            recall >= 0.90,
            "SQ8 path recall@10 = {recall}, want >= 0.90"
        );
    }

    #[test]
    fn segment_roundtrips_through_cbor() {
        let seg = IndexSegment::build(
            vec![hash_typed(b"m:", b"1")],
            vec![
                chunk(0, "alpha beta", None),
                chunk_with_vec(1, "gamma", vec![0.6, 0.8]),
            ],
        );
        let bytes = crate::canonical::to_cbor(&seg).unwrap();
        let back: IndexSegment = crate::canonical::from_cbor(&bytes).unwrap();
        assert_eq!(seg, back);
    }
}
