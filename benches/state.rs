use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::db::Database;
use tempfile::TempDir;

fn bench_state_set_get(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let db_root = dir.path().join("db");
    Database::init(&db_root).unwrap();
    let db = Database::open(&db_root).unwrap();

    let root = db.state_store.empty_root().unwrap();

    c.bench_function("state_set_single", |b| {
        b.iter(|| {
            db.state_store.set(root, b"bench_key", b"bench_value").unwrap();
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
        root = db.state_store.set(root, key.as_bytes(), val.as_bytes()).unwrap();
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

    // Compact state for realistic proof sizes
    let mut root = db.state_store.empty_root().unwrap();
    for i in 0u32..100 {
        let key = format!("key_{i:04}");
        root = db.state_store.set(root, key.as_bytes(), b"v").unwrap();
    }
    root = db.state_store.compact(root).unwrap();

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
}

criterion_group!(benches, bench_state_set_get, bench_state_compact, bench_state_proof);
criterion_main!(benches);
