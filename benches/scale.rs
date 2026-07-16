//! Scale points behind the BENCHMARKS.md claims: BM25 at 100k chunks,
//! vectors at production dimensionality (1536d), and coalesced single-op
//! writes under concurrency. Run: cargo bench --bench scale

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::manifest::{ChunkManifest, ChunkingSpec};
use neleus_db::{Database, Hash};
use tempfile::TempDir;

const BM25_CHUNKS: usize = 100_000;
const VEC_COUNT: usize = 10_000;
const VEC_DIM: usize = 1536;

fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

const VOCAB: &[&str] = &[
    "agent",
    "context",
    "retrieval",
    "memory",
    "vector",
    "index",
    "commit",
    "proof",
    "merkle",
    "search",
    "latency",
    "tenant",
    "policy",
    "session",
    "chunk",
    "document",
    "embedding",
    "knowledge",
    "audit",
    "replay",
    "state",
    "history",
    "filter",
    "rank",
    "fusion",
    "query",
    "storage",
    "engine",
    "graph",
    "summary",
    "temporal",
    "validity",
    "secure",
    "verify",
];

fn corpus_text(rng: &mut impl FnMut() -> u64, chunks: usize, words_per_chunk: usize) -> String {
    let mut out = String::with_capacity(chunks * words_per_chunk * 8);
    for _ in 0..chunks * words_per_chunk {
        out.push_str(VOCAB[(rng() as usize) % VOCAB.len()]);
        out.push(' ');
    }
    out
}

fn synthetic_vec(rng: &mut impl FnMut() -> u64) -> Vec<f32> {
    (0..VEC_DIM)
        .map(|_| ((rng() % 2000) as f32 / 1000.0) - 1.0)
        .collect()
}

struct Fixture {
    _tmp: TempDir,
    engine: Engine,
    text_commit: Hash,
    vec_commit: Hash,
    query_vec: Vec<f32>,
}

fn setup() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let db = Database::open(&root).unwrap();
    let mut rng = lcg(42);

    // 100k text chunks as one document (avg ~12 words/chunk at 96B chunks).
    let text = corpus_text(&mut rng, BM25_CHUNKS, 12);

    // Component baseline: hashing alone, no IO, no index, one thread.
    {
        let chunks =
            neleus_db::manifest::chunk_fixed(text.as_bytes(), text.len() / BM25_CHUNKS, 0).unwrap();
        let start = Instant::now();
        let mut acc = 0u8;
        for c in &chunks {
            acc ^= neleus_db::hash::hash_blob(c).as_bytes()[0];
        }
        eprintln!(
            "[scale] blake3 hash-only, {} chunks, 1 thread: {:?} (sink {acc})",
            chunks.len(),
            start.elapsed()
        );
    }

    let start = Instant::now();
    let doc = db
        .manifest_store
        .put_doc_manifest_from_bytes(
            &db.blob_store,
            "corpus".into(),
            text.as_bytes(),
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: text.len() / BM25_CHUNKS,
                overlap: 0,
            },
            Some(1),
        )
        .unwrap();
    let text_commit = db
        .create_commit_at_head("text", "bench", "corpus", vec![doc])
        .unwrap();
    eprintln!(
        "[scale] {BM25_CHUNKS} chunk ingest in {:?}",
        start.elapsed()
    );

    // 10k x 1536d vectors on a separate head.
    let start = Instant::now();
    let mut manifests = Vec::with_capacity(VEC_COUNT);
    for i in 0..VEC_COUNT {
        let text_hash = db
            .blob_store
            .put(format!("vector chunk {i}").as_bytes())
            .unwrap();
        let emb = db
            .blob_store
            .put(&neleus_db::canonical::to_cbor(&synthetic_vec(&mut rng)).unwrap())
            .unwrap();
        manifests.push(
            db.manifest_store
                .put_manifest(&ChunkManifest {
                    schema_version: 3,
                    chunk_text: text_hash,
                    start: 0,
                    end: 16,
                    embedding: Some(emb),
                    metadata: None,
                })
                .unwrap(),
        );
    }
    let vec_commit = db
        .create_commit_at_head("vectors", "bench", "vectors", manifests)
        .unwrap();
    eprintln!(
        "[scale] {VEC_COUNT}x{VEC_DIM}d vector ingest in {:?}",
        start.elapsed()
    );

    let engine = Engine::new(db);
    let start = Instant::now();
    engine.ensure_indexed(text_commit).unwrap();
    eprintln!("[scale] text index build in {:?}", start.elapsed());
    let start = Instant::now();
    engine.ensure_indexed(vec_commit).unwrap();
    eprintln!(
        "[scale] vector index (HNSW {VEC_COUNT}x{VEC_DIM}d) build in {:?}",
        start.elapsed()
    );

    // Coalesced single-op writes: 8 writers x 250 ops, one-shot measurement.
    let writer = Arc::new(engine.coalescing_writer("text"));
    let start = Instant::now();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || {
                for i in 0..250 {
                    writer
                        .set(format!("k-{t}-{i}").as_bytes(), b"payload")
                        .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let elapsed = start.elapsed();
    drop(writer);
    eprintln!(
        "[scale] coalesced writes: 2000 single ops via 8 writers in {elapsed:?} = {:?}/op",
        elapsed / 2000
    );

    let mut qrng = lcg(99);
    Fixture {
        _tmp: tmp,
        engine,
        text_commit,
        vec_commit,
        query_vec: synthetic_vec(&mut qrng),
    }
}

fn bench_scale(c: &mut Criterion) {
    let f = setup();
    let filter = SearchFilter::default();

    let mut group = c.benchmark_group("bm25_top10_100k_chunks");
    group.measurement_time(Duration::from_secs(8));
    group.bench_function("neleus_maxscore", |b| {
        b.iter(|| {
            f.engine
                .search_semantic(f.text_commit, "vector retrieval latency", 10, &filter)
                .unwrap()
        });
    });
    group.finish();

    let mut group = c.benchmark_group("vector_top10_10k_x1536d");
    group.bench_function("neleus_hnsw_sq8", |b| {
        b.iter(|| {
            f.engine
                .search_vector(f.vec_commit, &f.query_vec, 10, &filter)
                .unwrap()
        });
    });
    group.finish();

    let mut group = c.benchmark_group("coalesced_single_write");
    group.sample_size(30);
    group.bench_function("neleus_coalesced_8writers", |b| {
        let writer = Arc::new(f.engine.coalescing_writer("text"));
        b.iter_custom(|iters| {
            // Per-op cost under 8-way concurrency, amortized.
            let per_thread = (iters as usize).div_ceil(8).max(1);
            let start = Instant::now();
            std::thread::scope(|s| {
                for t in 0..8 {
                    let writer = Arc::clone(&writer);
                    s.spawn(move || {
                        for i in 0..per_thread {
                            writer
                                .set(format!("b-{t}-{i}").as_bytes(), b"payload")
                                .unwrap();
                        }
                    });
                }
            });
            start
                .elapsed()
                .mul_f64(iters as f64 / (per_thread * 8) as f64)
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_scale
}
criterion_main!(benches);
