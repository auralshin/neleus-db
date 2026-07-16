//! HNSW for ANN search over L2-normalized embeddings; distance = 1 - dot.
//!
//! Zero-dep by policy. Recall pinned against the exact oracle in tests;
//! `exact_search` is also the fallback for small/filtered candidate sets.
//! Level assignment is splitmix64(node id): same vectors -> same graph.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Max neighbors per node on layers > 0.
const M: usize = 16;
/// Max neighbors per node on layer 0.
const M0: usize = 32;
/// Candidate-list size during construction.
const EF_CONSTRUCTION: usize = 128;
/// Default candidate-list size during search (callers can raise it).
pub const EF_SEARCH: usize = 96;

/// Nodes inserted sequentially before batched-parallel construction starts.
const BUILD_RAMP: usize = 1024;
/// Batch size for parallel candidate search during construction.
const BUILD_BATCH: usize = 256;

/// Multiplier for geometric level assignment: 1/ln(M).
fn level_for(node: u32) -> usize {
    // splitmix64 of the node id gives a uniform u64; deterministic by design.
    let mut x = (node as u64).wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    let u = ((x >> 11) as f64) / ((1u64 << 53) as f64); // uniform in [0,1)
    let ml = 1.0 / (M as f64).ln();
    (-(u.max(f64::MIN_POSITIVE)).ln() * ml) as usize
}

#[inline]
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    // 4-lane unroll; vectorizes at opt-level 3 without a SIMD dep.
    let n = a.len().min(b.len());
    let chunks = n / 4;
    let (mut s0, mut s1, mut s2, mut s3) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
    for i in 0..chunks {
        let j = i * 4;
        s0 += a[j] * b[j];
        s1 += a[j + 1] * b[j + 1];
        s2 += a[j + 2] * b[j + 2];
        s3 += a[j + 3] * b[j + 3];
    }
    let mut s = s0 + s1 + s2 + s3;
    for j in chunks * 4..n {
        s += a[j] * b[j];
    }
    s
}

#[inline]
pub fn normalize(v: &mut [f32]) -> bool {
    let norm = dot(v, v).sqrt();
    if norm == 0.0 || !norm.is_finite() {
        return false;
    }
    for x in v.iter_mut() {
        *x /= norm;
    }
    true
}

#[inline]
fn distance(a: &[f32], b: &[f32]) -> f32 {
    1.0 - dot(a, b)
}

/// SQ8: symmetric scalar quantization. Returns (codes, scale) with
/// x[i] ~= codes[i] as f32 * scale. Codes stored as u8 bit-patterns of i8
/// so segments serialize compactly.
pub fn quantize(v: &[f32]) -> (Vec<u8>, f32) {
    let max = v.iter().fold(0.0f32, |m, x| m.max(x.abs()));
    if max == 0.0 || !max.is_finite() {
        return (vec![0u8; v.len()], 0.0);
    }
    let scale = max / 127.0;
    let codes = v
        .iter()
        .map(|x| ((x / scale).round().clamp(-127.0, 127.0) as i8) as u8)
        .collect();
    (codes, scale)
}

/// Integer dot over i8 codes (stored as u8 bit-patterns); i32 accumulation
/// auto-vectorizes. ~4x the throughput of the f32 path at high dims.
#[inline]
pub fn dot_q(a: &[u8], b: &[u8]) -> i32 {
    let n = a.len().min(b.len());
    let chunks = n / 4;
    let (mut s0, mut s1, mut s2, mut s3) = (0i32, 0i32, 0i32, 0i32);
    for i in 0..chunks {
        let j = i * 4;
        s0 += (a[j] as i8 as i32) * (b[j] as i8 as i32);
        s1 += (a[j + 1] as i8 as i32) * (b[j + 1] as i8 as i32);
        s2 += (a[j + 2] as i8 as i32) * (b[j + 2] as i8 as i32);
        s3 += (a[j + 3] as i8 as i32) * (b[j + 3] as i8 as i32);
    }
    let mut s = s0 + s1 + s2 + s3;
    for j in chunks * 4..n {
        s += (a[j] as i8 as i32) * (b[j] as i8 as i32);
    }
    s
}

/// Max-heap by distance: root = worst result, popped on closer candidate.
#[derive(PartialEq)]
struct Far(f32, u32);
impl Eq for Far {}
impl PartialOrd for Far {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Far {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.partial_cmp(&other.0).unwrap_or(Ordering::Equal)
    }
}

/// Min-heap entry by distance (via reversed ordering inside a BinaryHeap).
#[derive(PartialEq)]
struct Near(f32, u32);
impl Eq for Near {}
impl PartialOrd for Near {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Near {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.partial_cmp(&self.0).unwrap_or(Ordering::Equal)
    }
}

/// Graph only; vectors live in the segment so exact-scan shares them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HnswGraph {
    pub entry_point: u32,
    pub max_level: u32,
    /// `links[node][layer]` = neighbor node ids; `links[node].len()` is the
    /// node's level + 1, layer 0 is the bottom (dense) layer.
    pub links: Vec<Vec<Vec<u32>>>,
}

impl HnswGraph {
    /// Build a graph over `vectors` (already normalized, all same dim).
    pub fn build(vectors: &[Vec<f32>]) -> Option<Self> {
        let dist = |a: u32, b: u32| distance(&vectors[a as usize], &vectors[b as usize]);
        Self::build_core(vectors.len(), &dist)
    }

    /// Build over the SQ8 quantized metric. At high dims this moves 4x less
    /// memory per distance, which is where construction time goes; the
    /// query path reranks candidates with f32, so end recall is pinned by
    /// the same oracle tests as the f32 build.
    pub fn build_quantized(codes: &[Vec<u8>], scales: &[f32]) -> Option<Self> {
        let dist = |a: u32, b: u32| {
            let (a, b) = (a as usize, b as usize);
            1.0 - dot_q(&codes[a], &codes[b]) as f32 * scales[a] * scales[b]
        };
        Self::build_core(codes.len(), &dist)
    }

    fn build_core(n: usize, dist: &(dyn Fn(u32, u32) -> f32 + Sync)) -> Option<Self> {
        if n == 0 {
            return None;
        }
        let mut links: Vec<Vec<Vec<u32>>> = (0..n)
            .map(|i| vec![Vec::new(); level_for(i as u32) + 1])
            .collect();
        let mut entry_point = 0u32;
        let mut max_level = links[0].len() - 1;

        // Ramp: first nodes insert sequentially so the early graph is dense
        // enough that frozen-snapshot searches stay accurate.
        let ramp_end = n.min(BUILD_RAMP) as u32;
        for node in 1..ramp_end {
            let found = search_candidates(dist, &links, entry_point, max_level, node);
            apply_insert(
                dist,
                &mut links,
                node,
                found,
                &mut entry_point,
                &mut max_level,
            );
        }

        // Batched-parallel: candidate searches are pure reads against the
        // graph as of batch start, so they fan out across cores; link
        // application stays serial and ordered (deterministic output).
        // Batch-mates don't see each other during search; with batches this
        // small the recall cost is below noise (pinned by the oracle test).
        let mut next = ramp_end;
        while (next as usize) < n {
            let end = ((next as usize + BUILD_BATCH).min(n)) as u32;
            let batch: Vec<u32> = (next..end).collect();
            let frozen_links = &links;
            let (ep, ml) = (entry_point, max_level);
            let found: Vec<Vec<Vec<(f32, u32)>>> =
                crate::par::parallel_map(batch.clone(), |node| {
                    search_candidates(dist, frozen_links, ep, ml, node)
                });
            for (node, layers) in batch.into_iter().zip(found) {
                apply_insert(
                    dist,
                    &mut links,
                    node,
                    layers,
                    &mut entry_point,
                    &mut max_level,
                );
            }
            next = end;
        }

        // Trim construction slack so the serialized graph and query-time
        // traversal stay at m_max neighbors per node.
        for node in 0..n as u32 {
            for layer in 0..links[node as usize].len() {
                let m_max = if layer == 0 { M0 } else { M };
                if links[node as usize][layer].len() > m_max {
                    prune(dist, &mut links, node, layer, m_max);
                }
            }
        }

        Some(Self {
            entry_point,
            max_level: max_level as u32,
            links,
        })
    }

    /// Top-k search. `filter` gates results only — traversal still crosses
    /// non-matching nodes (keeps recall under selective filters). Returns
    /// `(cosine_similarity, node_id)` best-first.
    pub fn search(
        &self,
        vectors: &[Vec<f32>],
        query: &[f32],
        k: usize,
        ef: usize,
        filter: Option<&dyn Fn(u32) -> bool>,
    ) -> Vec<(f32, u32)> {
        self.search_with(
            &|node| distance(query, &vectors[node as usize]),
            vectors.len(),
            k,
            ef,
            filter,
        )
    }

    /// Search with an arbitrary node-distance function (the SQ8 traversal
    /// path). Returns `(1 - distance, node_id)` best-first.
    pub fn search_with(
        &self,
        node_dist: &dyn Fn(u32) -> f32,
        n_nodes: usize,
        k: usize,
        ef: usize,
        filter: Option<&dyn Fn(u32) -> bool>,
    ) -> Vec<(f32, u32)> {
        if n_nodes == 0 || k == 0 {
            return Vec::new();
        }
        let mut ep = self.entry_point;
        let mut level = self.max_level as usize;
        while level > 0 {
            ep = greedy_closest_with(node_dist, &self.links, ep, level);
            level -= 1;
        }
        let ef = ef.max(k);
        let found = search_layer_with(node_dist, &self.links, n_nodes, &[ep], 0, ef, filter);
        found
            .into_iter()
            .take(k)
            .map(|(d, id)| (1.0 - d, id))
            .collect()
    }
}

/// Read-only insertion search: greedy descent above the node's level, then
/// ef_construction beam per layer. Returns per-layer candidates, layer 0 last.
fn search_candidates(
    dist: &(dyn Fn(u32, u32) -> f32 + Sync),
    links: &[Vec<Vec<u32>>],
    entry_point: u32,
    max_level: usize,
    node: u32,
) -> Vec<Vec<(f32, u32)>> {
    let node_level = links[node as usize].len() - 1;
    let nd = |x: u32| dist(node, x);

    let mut ep = entry_point;
    let mut level = max_level;
    while level > node_level {
        ep = greedy_closest_with(&nd, links, ep, level);
        level -= 1;
    }

    let mut out = Vec::new();
    let mut eps = vec![ep];
    for layer in (0..=node_level.min(max_level)).rev() {
        let found = search_layer_with(&nd, links, links.len(), &eps, layer, EF_CONSTRUCTION, None);
        eps = found.iter().map(|&(_, id)| id).collect();
        if eps.is_empty() {
            eps = vec![ep];
        }
        out.push(found);
    }
    out
}

/// Mutating half of insertion: link `node` to its candidates per layer
/// (top layer first, matching `search_candidates` output order) and prune
/// overflowing neighbor lists.
fn apply_insert(
    dist: &(dyn Fn(u32, u32) -> f32 + Sync),
    links: &mut [Vec<Vec<u32>>],
    node: u32,
    per_layer: Vec<Vec<(f32, u32)>>,
    entry_point: &mut u32,
    max_level: &mut usize,
) {
    let node_level = links[node as usize].len() - 1;
    let top = node_level.min(*max_level);
    for (i, found) in per_layer.into_iter().enumerate() {
        let layer = top - i;
        let m_max = if layer == 0 { M0 } else { M };
        for &(_, neighbor) in found.iter().take(m_max) {
            links[node as usize][layer].push(neighbor);
            links[neighbor as usize][layer].push(node);
            // Slack: let lists overgrow to 2x before pruning back to m_max.
            // Halves prune frequency in the serial apply phase, which is
            // where build wall-time goes once searches are parallel.
            if links[neighbor as usize][layer].len() > m_max * 2 {
                prune(dist, links, neighbor, layer, m_max);
            }
        }
    }
    if node_level > *max_level {
        *max_level = node_level;
        *entry_point = node;
    }
}

fn greedy_closest_with(
    node_dist: &dyn Fn(u32) -> f32,
    links: &[Vec<Vec<u32>>],
    start: u32,
    layer: usize,
) -> u32 {
    let mut best = start;
    let mut best_d = node_dist(start);
    loop {
        let mut improved = false;
        let neighbors = links[best as usize].get(layer);
        if let Some(neighbors) = neighbors {
            for &n in neighbors {
                let d = node_dist(n);
                if d < best_d {
                    best_d = d;
                    best = n;
                    improved = true;
                }
            }
        }
        if !improved {
            return best;
        }
    }
}

/// Beam search on one layer; up to `ef` `(distance, node)` nearest-first.
fn search_layer_with(
    node_dist: &dyn Fn(u32) -> f32,
    links: &[Vec<Vec<u32>>],
    n_nodes: usize,
    entry_points: &[u32],
    layer: usize,
    ef: usize,
    filter: Option<&dyn Fn(u32) -> bool>,
) -> Vec<(f32, u32)> {
    let mut visited = vec![false; n_nodes];
    let mut candidates: BinaryHeap<Near> = BinaryHeap::new();
    let mut results: BinaryHeap<Far> = BinaryHeap::new();

    for &ep in entry_points {
        if visited[ep as usize] {
            continue;
        }
        visited[ep as usize] = true;
        let d = node_dist(ep);
        candidates.push(Near(d, ep));
        if filter.map(|f| f(ep)).unwrap_or(true) {
            results.push(Far(d, ep));
        }
    }

    while let Some(Near(d, node)) = candidates.pop() {
        let worst = results.peek().map(|f| f.0).unwrap_or(f32::INFINITY);
        if d > worst && results.len() >= ef {
            break;
        }
        if let Some(neighbors) = links[node as usize].get(layer) {
            for &n in neighbors {
                if visited[n as usize] {
                    continue;
                }
                visited[n as usize] = true;
                let nd = node_dist(n);
                let worst = results.peek().map(|f| f.0).unwrap_or(f32::INFINITY);
                if nd < worst || results.len() < ef {
                    candidates.push(Near(nd, n));
                    if filter.map(|f| f(n)).unwrap_or(true) {
                        results.push(Far(nd, n));
                        if results.len() > ef {
                            results.pop();
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<(f32, u32)> = results.into_iter().map(|Far(d, id)| (d, id)).collect();
    out.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    out
}

/// Keep only the `m_max` closest neighbors of `node` on `layer`.
/// Distances are computed once per candidate, not per comparison.
fn prune(
    dist: &(dyn Fn(u32, u32) -> f32 + Sync),
    links: &mut [Vec<Vec<u32>>],
    node: u32,
    layer: usize,
    m_max: usize,
) {
    let list = &mut links[node as usize][layer];
    let mut scored: Vec<(f32, u32)> = list.iter().map(|&x| (dist(node, x), x)).collect();
    scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    // Duplicate ids share a distance, so they sort adjacent.
    scored.dedup_by_key(|e| e.1);
    list.clear();
    list.extend(scored.into_iter().take(m_max).map(|(_, id)| id));
}

/// Exact top-k scan: oracle + fallback path.
pub fn exact_search(
    vectors: &[Vec<f32>],
    query: &[f32],
    k: usize,
    filter: Option<&dyn Fn(u32) -> bool>,
) -> Vec<(f32, u32)> {
    let mut hits: Vec<(f32, u32)> = vectors
        .iter()
        .enumerate()
        .filter(|(i, v)| v.len() == query.len() && filter.map(|f| f(*i as u32)).unwrap_or(true))
        .map(|(i, v)| (dot(query, v), i as u32))
        .collect();
    hits.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
    hits.truncate(k);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random unit vectors.
    fn synthetic_vectors(n: usize, dim: usize) -> Vec<Vec<f32>> {
        (0..n)
            .map(|i| {
                let mut v: Vec<f32> = (0..dim)
                    .map(|j| {
                        let mut x = (i * dim + j) as u64;
                        x = x.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(31);
                        ((x % 2000) as f32 / 1000.0) - 1.0
                    })
                    .collect();
                assert!(normalize(&mut v));
                v
            })
            .collect()
    }

    #[test]
    fn build_is_deterministic() {
        let vs = synthetic_vectors(500, 32);
        let a = HnswGraph::build(&vs).unwrap();
        let b = HnswGraph::build(&vs).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn recall_at_10_beats_090_vs_exact_oracle() {
        let vs = synthetic_vectors(2000, 32);
        let graph = HnswGraph::build(&vs).unwrap();

        let queries = synthetic_vectors(50, 32);
        let mut total_overlap = 0usize;
        for q in &queries {
            let exact: std::collections::HashSet<u32> = exact_search(&vs, q, 10, None)
                .into_iter()
                .map(|(_, i)| i)
                .collect();
            let approx = graph.search(&vs, q, 10, EF_SEARCH, None);
            total_overlap += approx.iter().filter(|(_, i)| exact.contains(i)).count();
        }
        let recall = total_overlap as f32 / (queries.len() * 10) as f32;
        assert!(recall >= 0.90, "HNSW recall@10 = {recall}, want >= 0.90");
    }

    #[test]
    fn filtered_search_only_returns_matching_nodes() {
        let vs = synthetic_vectors(1000, 16);
        let graph = HnswGraph::build(&vs).unwrap();
        let q = &vs[3];
        let filter = |id: u32| id.is_multiple_of(2);
        let hits = graph.search(&vs, q, 10, EF_SEARCH, Some(&filter));
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|(_, id)| id.is_multiple_of(2)));
    }

    #[test]
    fn exact_search_orders_by_similarity() {
        let vs = synthetic_vectors(100, 8);
        let hits = exact_search(&vs, &vs[7], 5, None);
        assert_eq!(hits[0].1, 7);
        assert!(hits.windows(2).all(|w| w[0].0 >= w[1].0));
    }

    #[test]
    fn single_vector_graph_works() {
        let vs = synthetic_vectors(1, 8);
        let graph = HnswGraph::build(&vs).unwrap();
        let hits = graph.search(&vs, &vs[0], 5, EF_SEARCH, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, 0);
    }

    #[test]
    fn empty_input_builds_nothing() {
        assert!(HnswGraph::build(&[]).is_none());
    }

    #[test]
    fn graph_roundtrips_through_cbor() {
        let vs = synthetic_vectors(200, 16);
        let graph = HnswGraph::build(&vs).unwrap();
        let bytes = crate::canonical::to_cbor(&graph).unwrap();
        let back: HnswGraph = crate::canonical::from_cbor(&bytes).unwrap();
        assert_eq!(graph, back);
    }
}
