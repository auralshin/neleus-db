//! Retrieval quality on a real corpus with real embeddings and real relevance
//! judgments (BEIR/SciFact), reporting nDCG@10 and Recall@10 for BM25, vector,
//! and hybrid search, plus per-query latency.
//!
//! The synthetic corpora used elsewhere in `benches/` measure speed, not
//! quality: a 34-word vocabulary and pseudo-random unit vectors say nothing
//! about whether the ranking is any good. This says.
//!
//! ```text
//! cargo run --release --example 07_retrieval_quality -- corpus_emb.jsonl queries_emb.jsonl
//! ```
//!
//! Both inputs are JSONL. Corpus: `{"id","text","emb":[f32]}`.
//! Queries: `{"id","text","emb":[f32],"rel":[doc ids]}`.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use neleus_db::canonical::to_cbor;
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::manifest::ChunkManifest;
use neleus_db::{Database, Hash};

const TOP_K: usize = 10;

struct Doc {
    id: String,
    text: String,
    emb: Vec<f32>,
}

struct Query {
    text: String,
    emb: Vec<f32>,
    rel: Vec<String>,
}

fn read_jsonl(path: &str) -> Result<Vec<serde_json::Value>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(Into::into))
        .collect()
}

fn floats(v: &serde_json::Value) -> Vec<f32> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_f64())
                .map(|x| x as f32)
                .collect()
        })
        .unwrap_or_default()
}

/// Binary-relevance nDCG@k: gains are 1 for judged-relevant, 0 otherwise.
fn ndcg_at_k(ranked: &[String], rel: &[String], k: usize) -> f64 {
    let dcg: f64 = ranked
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, d)| {
            if rel.contains(d) {
                1.0 / ((i + 2) as f64).log2()
            } else {
                0.0
            }
        })
        .sum();
    let ideal: f64 = (0..rel.len().min(k))
        .map(|i| 1.0 / ((i + 2) as f64).log2())
        .sum();
    if ideal == 0.0 { 0.0 } else { dcg / ideal }
}

fn recall_at_k(ranked: &[String], rel: &[String], k: usize) -> f64 {
    if rel.is_empty() {
        return 0.0;
    }
    let hit = ranked.iter().take(k).filter(|d| rel.contains(d)).count();
    hit as f64 / rel.len() as f64
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [corpus_path, queries_path] = args.as_slice() else {
        bail!("usage: 07_retrieval_quality <corpus_emb.jsonl> <queries_emb.jsonl>");
    };

    let docs: Vec<Doc> = read_jsonl(corpus_path)?
        .into_iter()
        .map(|v| Doc {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            text: v["text"].as_str().unwrap_or_default().to_string(),
            emb: floats(&v["emb"]),
        })
        .collect();
    let queries: Vec<Query> = read_jsonl(queries_path)?
        .into_iter()
        .map(|v| Query {
            text: v["text"].as_str().unwrap_or_default().to_string(),
            emb: floats(&v["emb"]),
            rel: v["rel"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();
    let dim = docs.first().map(|d| d.emb.len()).unwrap_or(0);
    if dim == 0 || docs.is_empty() || queries.is_empty() {
        bail!("empty corpus, empty queries, or missing embeddings");
    }
    eprintln!(
        "[beir] {} docs, {} judged queries, {dim}-dim embeddings",
        docs.len(),
        queries.len()
    );

    let tmp = tempfile::TempDir::new()?;
    let root = tmp.path().join("db");
    Database::init(&root)?;
    let engine = Engine::open(&root)?;
    let db = engine.db();

    // Ingest: one ChunkManifest per document, so a hit maps back to a doc id.
    let start = Instant::now();
    let mut by_chunk: HashMap<Hash, String> = HashMap::new();
    let mut manifests = Vec::with_capacity(docs.len());
    for d in &docs {
        let text_hash = db.blob_store.put(d.text.as_bytes())?;
        let emb_hash = db.blob_store.put(&to_cbor(&d.emb)?)?;
        by_chunk.insert(text_hash, d.id.clone());
        manifests.push(db.manifest_store.put_manifest(&ChunkManifest {
            schema_version: neleus_db::manifest::MANIFEST_SCHEMA_VERSION,
            chunk_text: text_hash,
            start: 0,
            end: d.text.len(),
            embedding: Some(emb_hash),
            metadata: None,
        })?);
    }
    let commit = db.create_commit_at_head("main", "beir", "scifact", manifests)?;
    eprintln!("[beir] ingest in {:?}", start.elapsed());

    let start = Instant::now();
    engine.ensure_indexed(commit)?;
    eprintln!("[beir] index build in {:?}", start.elapsed());

    let filter = SearchFilter::default();
    let mut rows: Vec<(&str, f64, f64, f64)> = Vec::new();

    for mode in ["bm25", "vector", "hybrid"] {
        let (mut ndcg, mut recall) = (0.0, 0.0);
        let start = Instant::now();
        for q in &queries {
            let hits = match mode {
                "bm25" => engine.search_semantic(commit, &q.text, TOP_K, &filter)?,
                "vector" => engine.search_vector(commit, &q.emb, TOP_K, &filter)?,
                _ => engine.search_hybrid(commit, Some(&q.text), Some(&q.emb), TOP_K, &filter)?,
            };
            let ranked: Vec<String> = hits
                .iter()
                .filter_map(|h| by_chunk.get(&h.chunk_hash).cloned())
                .collect();
            ndcg += ndcg_at_k(&ranked, &q.rel, TOP_K);
            recall += recall_at_k(&ranked, &q.rel, TOP_K);
        }
        let n = queries.len() as f64;
        let per_query = start.elapsed().as_secs_f64() * 1e6 / n;
        rows.push((mode, ndcg / n, recall / n, per_query));
    }

    println!(
        "\ncorpus: {} docs, {dim}-dim, {} judged queries, top-{TOP_K}",
        docs.len(),
        queries.len()
    );
    println!(
        "{:<8} {:>10} {:>11} {:>14}",
        "mode", "nDCG@10", "Recall@10", "latency/query"
    );
    println!("{}", "-".repeat(46));
    for (mode, ndcg, recall, us) in rows {
        println!("{mode:<8} {ndcg:>10.4} {recall:>11.4} {us:>11.1} µs");
    }
    Ok(())
}
