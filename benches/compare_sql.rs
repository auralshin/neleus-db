//! neleus engine vs SQLite (WAL + FTS5, file-backed) on the same corpus:
//! 10k text chunks, 5k 128-dim embeddings, 10k KV pairs. SQLite has no
//! native vector index, so vector rows are neleus-only. Postgres/SQLCipher
//! comparisons live in BENCHMARKS.md. Run: cargo bench --bench compare_sql

use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::manifest::ChunkManifest;
use neleus_db::{Database, Hash};
use rusqlite::Connection;
use tempfile::TempDir;

const N_CHUNKS: usize = 10_000;
const N_VECTORS: usize = 5_000;
const N_KV: usize = 10_000;
const DIM: usize = 128;
const COMMITS: usize = 5; // spread ingest to exercise delta+merge

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

fn synthetic_text(rng: &mut impl FnMut() -> u64, words: usize) -> String {
    (0..words)
        .map(|_| VOCAB[(rng() as usize) % VOCAB.len()])
        .collect::<Vec<_>>()
        .join(" ")
}

fn synthetic_vec(rng: &mut impl FnMut() -> u64) -> Vec<f32> {
    (0..DIM)
        .map(|_| ((rng() % 2000) as f32 / 1000.0) - 1.0)
        .collect()
}

struct NeleusFixture {
    _tmp: TempDir,
    engine: Engine,
    commit: Hash,
    query_vec: Vec<f32>,
}

fn setup_neleus() -> NeleusFixture {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let db = Database::open(&root).unwrap();

    let mut rng = lcg(42);
    let start = Instant::now();
    let mut commit = Hash::zero();
    let per_commit = N_CHUNKS / COMMITS;
    for c in 0..COMMITS {
        let mut manifests = Vec::with_capacity(per_commit);
        for i in 0..per_commit {
            let id = c * per_commit + i;
            let text = synthetic_text(&mut rng, 12);
            let text_hash = db.blob_store.put(text.as_bytes()).unwrap();
            let embedding = if id < N_VECTORS {
                let v = synthetic_vec(&mut rng);
                Some(
                    db.blob_store
                        .put(&neleus_db::canonical::to_cbor(&v).unwrap())
                        .unwrap(),
                )
            } else {
                None
            };
            let m = ChunkManifest {
                schema_version: 3,
                chunk_text: text_hash,
                start: 0,
                end: text.len(),
                embedding,
                metadata: None,
            };
            manifests.push(db.manifest_store.put_manifest(&m).unwrap());
        }
        commit = db
            .create_commit_at_head("main", "bench", &format!("batch {c}"), manifests)
            .unwrap();
    }
    // KV corpus.
    let mut rng_kv = lcg(7);
    for batch in 0..(N_KV / 1000) {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..1000)
            .map(|i| {
                let k = format!("key-{:08}", batch * 1000 + i).into_bytes();
                let v = format!("value-{}", rng_kv()).into_bytes();
                (k, v)
            })
            .collect();
        let refs: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        db.state_set_many_at_head("main", &refs).unwrap();
    }
    let ingest = start.elapsed();

    let engine = Engine::new(db);
    let start_index = Instant::now();
    engine.ensure_indexed(commit).unwrap();
    let index_time = start_index.elapsed();
    eprintln!(
        "[neleus] ingest {N_CHUNKS} chunks + {N_KV} kv in {ingest:?}; index build {index_time:?}"
    );

    let mut qrng = lcg(99);
    NeleusFixture {
        _tmp: tmp,
        engine,
        commit,
        query_vec: synthetic_vec(&mut qrng),
    }
}

struct SqliteFixture {
    _tmp: TempDir,
    conn: Connection,
}

fn setup_sqlite() -> SqliteFixture {
    let tmp = TempDir::new().unwrap();
    let conn = Connection::open(tmp.path().join("bench.sqlite")).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
    conn.execute_batch(
        "CREATE TABLE kv (key BLOB PRIMARY KEY, value BLOB);
         CREATE VIRTUAL TABLE chunks USING fts5(text);",
    )
    .unwrap();

    let start = Instant::now();
    let mut rng = lcg(42);
    {
        let tx = conn.unchecked_transaction().unwrap();
        let mut insert = tx.prepare("INSERT INTO chunks(text) VALUES (?1)").unwrap();
        for _ in 0..N_CHUNKS {
            let text = synthetic_text(&mut rng, 12);
            insert.execute([&text]).unwrap();
            if N_VECTORS > 0 {
                // burn the same rng draws as neleus for corpus parity
                let _ = synthetic_vec(&mut rng);
            }
        }
        drop(insert);
        tx.commit().unwrap();
    }
    {
        let mut rng_kv = lcg(7);
        let tx = conn.unchecked_transaction().unwrap();
        let mut insert = tx
            .prepare("INSERT OR REPLACE INTO kv(key, value) VALUES (?1, ?2)")
            .unwrap();
        for i in 0..N_KV {
            insert
                .execute((
                    format!("key-{i:08}").into_bytes(),
                    format!("value-{}", rng_kv()).into_bytes(),
                ))
                .unwrap();
        }
        drop(insert);
        tx.commit().unwrap();
    }
    eprintln!("[sqlite] ingest in {:?}", start.elapsed());
    SqliteFixture { _tmp: tmp, conn }
}

fn bench_compare(c: &mut Criterion) {
    let neleus = setup_neleus();
    let sqlite = setup_sqlite();
    let filter = SearchFilter::default();

    let mut group = c.benchmark_group("point_get_warm");
    group.bench_function("neleus_state_get", |b| {
        let db = neleus.engine.db();
        let root = db.resolve_state_root("main").unwrap();
        let mut i = 0usize;
        b.iter(|| {
            let key = format!("key-{:08}", i % N_KV);
            i += 1;
            db.state_store.get(root, key.as_bytes()).unwrap().unwrap()
        });
    });
    group.bench_function("sqlite_select", |b| {
        let mut stmt = sqlite
            .conn
            .prepare("SELECT value FROM kv WHERE key = ?1")
            .unwrap();
        let mut i = 0usize;
        b.iter(|| {
            let key = format!("key-{:08}", i % N_KV);
            i += 1;
            stmt.query_row([key.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
        });
    });
    group.finish();

    let mut group = c.benchmark_group("point_set_durable");
    group.sample_size(50);
    group.bench_function("neleus_state_set", |b| {
        let db = neleus.engine.db();
        let mut i = 0usize;
        b.iter(|| {
            let key = format!("bench-set-{i}");
            i += 1;
            db.state_set_at_head("main", key.as_bytes(), b"payload-0123456789")
                .unwrap()
        });
    });
    group.bench_function("sqlite_insert", |b| {
        let mut stmt = sqlite
            .conn
            .prepare("INSERT OR REPLACE INTO kv(key, value) VALUES (?1, ?2)")
            .unwrap();
        let mut i = 0usize;
        b.iter(|| {
            let key = format!("bench-set-{i}");
            i += 1;
            stmt.execute((key.as_bytes(), &b"payload-0123456789"[..]))
                .unwrap()
        });
    });
    group.finish();

    let mut group = c.benchmark_group("bm25_top10_10k_chunks");
    group.bench_function("neleus_semantic", |b| {
        b.iter(|| {
            neleus
                .engine
                .search_semantic(neleus.commit, "vector retrieval latency", 10, &filter)
                .unwrap()
        });
    });
    group.bench_function("sqlite_fts5", |b| {
        let mut stmt = sqlite
            .conn
            .prepare("SELECT rowid, rank FROM chunks WHERE chunks MATCH ?1 ORDER BY rank LIMIT 10")
            .unwrap();
        b.iter(|| {
            let rows: Vec<(i64, f64)> = stmt
                .query_map(["vector retrieval latency"], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        });
    });
    group.finish();

    // No SQL row here: stock SQLite/Postgres have no native ANN index.
    let mut group = c.benchmark_group("vector_top10_5k_x128d");
    group.bench_function("neleus_hnsw", |b| {
        b.iter(|| {
            neleus
                .engine
                .search_vector(neleus.commit, &neleus.query_vec, 10, &filter)
                .unwrap()
        });
    });
    group.finish();

    let mut group = c.benchmark_group("hybrid_top10");
    group.bench_function("neleus_rrf", |b| {
        b.iter(|| {
            neleus
                .engine
                .search_hybrid(
                    neleus.commit,
                    Some("vector retrieval latency"),
                    Some(&neleus.query_vec),
                    10,
                    &filter,
                )
                .unwrap()
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_compare
}
criterion_main!(benches);
