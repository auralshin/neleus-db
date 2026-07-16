use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::audit;
use neleus_db::canonical::to_cbor;
use neleus_db::db::Database;
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::manifest::{ChunkManifest, ChunkingSpec};
use neleus_db::retrieval_proof::{prove_chunk, verify_chunk_proof};
use tempfile::TempDir;

fn bench_state_set_get(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    let root = db.state_store.empty_root().unwrap();

    c.bench_function("state_set_single", |b| {
        b.iter(|| {
            db.state_store
                .set(root, b"bench_key", b"bench_value")
                .unwrap();
        });
    });

    let populated = db.state_store.set(root, b"k1", b"v1").unwrap();
    c.bench_function("state_get_hit", |b| {
        b.iter(|| {
            db.state_store.get(populated, b"k1").unwrap();
        });
    });

    c.bench_function("state_get_miss", |b| {
        b.iter(|| {
            db.state_store.get(populated, b"missing").unwrap();
        });
    });
}

fn bench_state_compact(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    // Build a state with many segments to compact
    let mut root = db.state_store.empty_root().unwrap();
    for i in 0u32..50 {
        let key = format!("key_{i:04}");
        let val = format!("value_{i:04}");
        root = db
            .state_store
            .set(root, key.as_bytes(), val.as_bytes())
            .unwrap();
    }

    c.bench_function("state_compact_50_segments", |b| {
        b.iter(|| {
            db.state_store.compact(root).unwrap();
        });
    });
}

fn bench_state_proof(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    let mut root = db.state_store.empty_root().unwrap();
    for i in 0u32..100 {
        let key = format!("key_{i:04}");
        root = db.state_store.set(root, key.as_bytes(), b"v").unwrap();
    }

    // Proof size (serialized bytes) and verification time, not just generation.
    let incl = db.state_store.proof(root, b"key_0042").unwrap();
    let excl = db.state_store.proof(root, b"zzz_absent").unwrap();
    eprintln!(
        "[proofs] state proof bytes (100 keys): inclusion {}, non-inclusion {}",
        to_cbor(&incl).unwrap().len(),
        to_cbor(&excl).unwrap().len()
    );

    c.bench_function("state_proof_inclusion", |b| {
        b.iter(|| {
            db.state_store.proof(root, b"key_0042").unwrap();
        });
    });

    c.bench_function("state_proof_non_inclusion", |b| {
        b.iter(|| {
            db.state_store.proof(root, b"zzz_absent").unwrap();
        });
    });

    c.bench_function("state_verify_inclusion", |b| {
        b.iter(|| db.state_store.verify_proof(root, b"key_0042", &incl));
    });

    c.bench_function("state_verify_non_inclusion", |b| {
        b.iter(|| db.state_store.verify_proof(root, b"zzz_absent", &excl));
    });
}

fn bench_chunk_proof(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    // Ingest a small document, then stack commits so the proof walks ancestry.
    let text = "the quick brown fox jumps over the lazy dog ".repeat(64);
    let doc = db
        .manifest_store
        .put_doc_manifest_from_bytes(
            &db.blob_store,
            "doc".into(),
            text.as_bytes(),
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 64,
                overlap: 0,
            },
            Some(1),
        )
        .unwrap();
    let mut commit = db
        .create_commit_at_head("main", "bench", "doc", vec![doc])
        .unwrap();

    const DEPTH: usize = 8;
    for i in 0..DEPTH {
        let t = db.blob_store.put(format!("filler {i}").as_bytes()).unwrap();
        let m = db
            .manifest_store
            .put_manifest(&ChunkManifest {
                schema_version: 3,
                chunk_text: t,
                start: 0,
                end: 8,
                embedding: None,
                metadata: None,
            })
            .unwrap();
        commit = db
            .create_commit_at_head("main", "bench", "filler", vec![m])
            .unwrap();
    }

    let chunk = db.manifest_store.get_doc_manifest(doc).unwrap().chunks[0];

    let proof = prove_chunk(&db, commit, chunk, true).unwrap();
    verify_chunk_proof(&proof).unwrap();
    eprintln!(
        "[proofs] chunk proof bytes (ancestry depth {}, content included): {}",
        DEPTH + 1,
        to_cbor(&proof).unwrap().len()
    );

    c.bench_function("chunk_proof_generate", |b| {
        b.iter(|| prove_chunk(&db, commit, chunk, true).unwrap());
    });

    c.bench_function("chunk_proof_verify", |b| {
        b.iter(|| verify_chunk_proof(&proof).unwrap());
    });
}

fn bench_audit_bundle(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    let text =
        "agent context retrieval memory vector index commit proof merkle search ".repeat(128);
    let doc = db
        .manifest_store
        .put_doc_manifest_from_bytes(
            &db.blob_store,
            "doc".into(),
            text.as_bytes(),
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 64,
                overlap: 0,
            },
            Some(1),
        )
        .unwrap();
    let doc_commit = db
        .create_commit_at_head("main", "bench", "doc", vec![doc])
        .unwrap();

    let engine = Engine::new(db);
    engine.ensure_indexed(doc_commit).unwrap();
    let filter = SearchFilter::default();

    // Record N retrievals; commit each QueryManifest so the audit walk finds it.
    const RETRIEVALS: usize = 64;
    for _ in 0..RETRIEVALS {
        let hits = engine
            .search_semantic(doc_commit, "vector retrieval proof", 10, &filter)
            .unwrap();
        let qm = engine
            .record_query(
                doc_commit,
                "semantic",
                Some("vector retrieval proof"),
                None,
                10,
                &filter,
                Some("bench"),
                &hits,
            )
            .unwrap();
        engine
            .db()
            .create_commit_at_head("main", "bench", "audit", vec![qm])
            .unwrap();
    }

    let out = dir.path().join("bundle.nelaudit");
    let summary = audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    audit::verify_bundle(&out, None, false).unwrap();
    eprintln!(
        "[proofs] audit bundle bytes ({} retrievals, unsigned): {}",
        RETRIEVALS, summary.bytes
    );

    c.bench_function("audit_bundle_export_64", |b| {
        b.iter(|| audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap());
    });

    c.bench_function("audit_bundle_verify_64", |b| {
        b.iter(|| audit::verify_bundle(&out, None, false).unwrap());
    });
}

criterion_group!(
    benches,
    bench_state_set_get,
    bench_state_compact,
    bench_state_proof,
    bench_chunk_proof,
    bench_audit_bundle
);
criterion_main!(benches);
