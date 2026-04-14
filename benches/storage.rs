use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::blob_store::BlobStore;
use tempfile::TempDir;

fn bench_blob_put_get(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let bs = BlobStore::new(dir.path());
    bs.ensure_dir().unwrap();

    let payload = vec![0xABu8; 4096]; // 4 KiB

    c.bench_function("blob_put_4k", |b| {
        b.iter(|| {
            bs.put(&payload).unwrap();
        });
    });

    let hash = bs.put(&payload).unwrap();
    c.bench_function("blob_get_4k", |b| {
        b.iter(|| {
            bs.get(hash).unwrap();
        });
    });
}

fn bench_blob_put_compressed(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    // Enable compression
    let bs = BlobStore::with_runtime_options(dir.path(), false, true, None);
    bs.ensure_dir().unwrap();

    // Repetitive data compresses well
    let payload = b"hello world ".repeat(512);

    c.bench_function("blob_put_compressed_6k", |b| {
        b.iter(|| {
            bs.put(&payload).unwrap();
        });
    });

    let hash = bs.put(&payload).unwrap();
    c.bench_function("blob_get_compressed_6k", |b| {
        b.iter(|| {
            bs.get(hash).unwrap();
        });
    });
}

criterion_group!(benches, bench_blob_put_get, bench_blob_put_compressed);
criterion_main!(benches);
