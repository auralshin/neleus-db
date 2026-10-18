//! One agent turn end to end under the configured durability: a recorded
//! hybrid search, the run committed with its prompt, output and retrieved
//! chunks, and a memory write. Run: cargo bench --bench agent

mod common;

use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::canonical::to_cbor;
use neleus_db::engine::{Engine, SearchFilter};
use tempfile::TempDir;

fn q10_agent_turn(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("db");
    common::init_db(&root);
    let engine = Engine::open(&root).unwrap();
    let mut seed = 7u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed
    };
    let words = [
        "agent", "memory", "policy", "loan", "risk", "audit", "vector", "claim",
    ];
    let embed = |next: &mut dyn FnMut() -> u64| -> Vec<f32> {
        (0..128)
            .map(|_| (next() % 2000) as f32 / 1000.0 - 1.0)
            .collect()
    };
    let mut manifests = Vec::new();
    for i in 0..2000 {
        let text: Vec<&str> = (0..12).map(|_| words[(next() % 8) as usize]).collect();
        let chunk = neleus_db::manifest::ChunkManifest {
            schema_version: neleus_db::manifest::MANIFEST_SCHEMA_VERSION,
            chunk_text: engine
                .db()
                .blob_store
                .for_head("main")
                .put(format!("{} {i}", text.join(" ")).as_bytes())
                .unwrap(),
            start: 0,
            end: 1,
            embedding: Some(
                engine
                    .db()
                    .blob_store
                    .for_head("main")
                    .put(&to_cbor(&embed(&mut next)).unwrap())
                    .unwrap(),
            ),
            metadata: None,
        };
        manifests.push(engine.db().manifest_store.put_manifest(&chunk).unwrap());
    }
    engine.commit("main", "bench", "corpus", manifests).unwrap();
    let query = embed(&mut next);
    let prompt = "x".repeat(2048);

    let turn = |i: usize| {
        let t0 = Instant::now();
        let found = engine
            .search(
                "main",
                None,
                neleus_db::engine::SearchQuery::Hybrid {
                    text: Some("loan risk policy"),
                    embedding: Some(&query),
                },
                5,
                &SearchFilter::default(),
                Some("key:agent"),
            )
            .unwrap();
        let t1 = Instant::now();
        let blobs = engine.db().blob_store.for_head("main");
        let run = neleus_db::manifest::RunManifest {
            schema_version: neleus_db::manifest::MANIFEST_SCHEMA_VERSION,
            model: "model".into(),
            prompt: blobs.put(format!("{prompt}{i}").as_bytes()).unwrap(),
            tool_calls: vec![],
            inputs: vec![],
            outputs: vec![blobs.put(format!("answer {i}").as_bytes()).unwrap()],
            started_at: 0,
            ended_at: 0,
            provider: None,
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: found.hits.iter().map(|h| h.chunk_hash).collect(),
            sdk_version: None,
            agent_id: Some("agent".into()),
            trace_id: None,
            parent_span: None,
            delegated_from: None,
            subject: None,
        };
        let m = engine.db().manifest_store.put_manifest(&run).unwrap();
        engine.commit("main", "agent", "turn", vec![m]).unwrap();
        let t2 = Instant::now();
        engine
            .db()
            .state_set_at_head("main", format!("memory/{i}").as_bytes(), b"note")
            .unwrap();
        (t1 - t0, t2 - t1, t2.elapsed())
    };

    let n = 50;
    let parts: Vec<_> = (0..n).map(turn).collect();
    let avg = |f: fn(
        &(
            std::time::Duration,
            std::time::Duration,
            std::time::Duration,
        ),
    ) -> std::time::Duration| {
        parts.iter().map(f).sum::<std::time::Duration>() / n as u32
    };
    eprintln!(
        "[q10] agent turn: recorded hybrid search {:?}, run commit {:?}, memory write {:?}",
        avg(|p| p.0),
        avg(|p| p.1),
        avg(|p| p.2)
    );
    let mut i = n;
    c.benchmark_group("q10_agent_turn")
        .sample_size(20)
        .bench_function("turn", |b| {
            b.iter(|| {
                i += 1;
                turn(i)
            })
        });
}

criterion_group!(benches, q10_agent_turn);
criterion_main!(benches);
