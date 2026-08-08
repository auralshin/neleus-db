//! Experiments backing the verifiability claims: checkpoint-chain scaling,
//! cold (auditor-side) verification cost, audit-bundle growth, and the BM25
//! cross-tenant statistics channel. Run: cargo bench --bench verifiability
//!
//! Measurements print to stderr with a `[q<N>]` tag; criterion timings cover
//! the paths that sit on an auditor's critical path.

use std::process::Command;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::audit;
use neleus_db::canonical::to_cbor;
use neleus_db::checkpoint::CheckpointStore;
use neleus_db::db::Database;
use neleus_db::engine::segment::{ChunkInput, IndexSegment};
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::hash::hash_typed;
use neleus_db::manifest::{ChunkMetadata, ChunkingSpec};
use tempfile::TempDir;

// ---------------------------------------------------------------- Q2
// Checkpoint chains are linear, so verification is O(J). Measure the
// constant and locate the length at which it stops being free.

fn q2_checkpoint_chain(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("db");
    Database::init(&root).unwrap();
    let db = Database::open(&root).unwrap();
    db.create_commit_at_head("main", "bench", "base", vec![])
        .unwrap();
    let store = CheckpointStore::new(&db);

    let mut group = c.benchmark_group("q2_checkpoint_chain_verify");
    let mut built = 0usize;
    for &target in &[1usize, 10, 100, 1_000, 10_000] {
        // Chains are append-only: extend rather than rebuild.
        let start = Instant::now();
        while built < target {
            store.create("main", None).unwrap();
            built += 1;
        }
        let build = start.elapsed();

        let report = store.verify_chain("main", None, false).unwrap();
        assert_eq!(report.length as usize, target);

        let start = Instant::now();
        let reps = if target >= 1_000 { 5 } else { 50 };
        for _ in 0..reps {
            store.verify_chain("main", None, false).unwrap();
        }
        let per = start.elapsed() / reps;
        eprintln!(
            "[q2] J={target:>6}: verify {per:>12.3?} ({:>8.3?}/checkpoint), append {build:?}",
            per / target as u32
        );
        group.bench_function(format!("J={target}"), |b| {
            b.iter(|| store.verify_chain("main", None, false).unwrap())
        });
    }
    group.finish();
}

// ---------------------------------------------------------------- Q3/Q4
// The auditor's real cost: a cold process verifying a bundle it was handed,
// with no database and no warm cache. Also the O(R) growth curve the paper
// previously reported only as a single point.

fn build_bundle(dir: &std::path::Path, retrievals: usize) -> (std::path::PathBuf, u64) {
    let root = dir.join(format!("db{retrievals}"));
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let text = "agent context retrieval memory vector index commit proof merkle search ".repeat(64);
    let (_doc, commit) = engine
        .put_document(
            "main",
            "corpus",
            text.as_bytes(),
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 64,
                overlap: 0,
            },
            None,
            "bench",
        )
        .unwrap();
    let filter = SearchFilter::default();
    for _ in 0..retrievals {
        let hits = engine
            .search_semantic(commit, "vector retrieval proof", 10, &filter)
            .unwrap();
        // Sequence-chained: identical retrievals would otherwise be one
        // content-addressed object, collapsing the R-scaling measurement.
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("vector retrieval proof"),
                None,
                10,
                &filter,
                Some("auditor-bench"),
                &hits,
            )
            .unwrap();
    }
    let out = dir.join(format!("bundle-{retrievals}.nelaudit"));
    let summary = audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    (out, summary.bytes)
}

fn q3_q4_auditor(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();

    // Bundle growth in the retrieval count.
    eprintln!("[q4] bundle growth (unsigned):");
    let mut sizes = Vec::new();
    for &r in &[1usize, 8, 64, 512] {
        let (path, bytes) = build_bundle(dir.path(), r);
        let start = Instant::now();
        let reps = 20;
        for _ in 0..reps {
            audit::verify_bundle(&path, None, false).unwrap();
        }
        let verify = start.elapsed() / reps;
        eprintln!(
            "[q4] R={r:>4}: {bytes:>9} B ({:>6.1} B/retrieval), in-process verify {verify:>10.3?} ({:>8.3?}/retrieval)",
            bytes as f64 / r as f64,
            verify / r as u32
        );
        sizes.push((r, path, bytes, verify));
    }

    // Q3: cold auditor. Spawn the standalone verifier as a fresh process, so
    // the number includes process start, dynamic linking, file read and
    // verification -- everything the auditor actually pays.
    let verifier = option_env!("CARGO_BIN_EXE_neleus-verify");
    match verifier {
        Some(bin) => {
            for (r, path, bytes, in_proc) in &sizes {
                let reps = 20;
                let start = Instant::now();
                for _ in 0..reps {
                    let status = Command::new(bin)
                        .arg(path)
                        .arg("--json")
                        .output()
                        .expect("spawn neleus-verify");
                    assert!(status.status.success(), "verifier rejected a valid bundle");
                }
                let cold = start.elapsed() / reps;
                eprintln!(
                    "[q3] R={r:>4} ({bytes} B): cold standalone verify {cold:>10.3?} \
                     (in-process {in_proc:>10.3?}; process overhead {:>10.3?})",
                    cold.saturating_sub(*in_proc)
                );
            }
        }
        None => eprintln!("[q3] CARGO_BIN_EXE_neleus-verify unset; skipped cold-process run"),
    }

    // Q3: cold *state* proof -- a freshly opened database with empty caches,
    // versus the warm path the paper previously reported.
    {
        let root = dir.path().join("state");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        let mut sroot = db.state_store.empty_root().unwrap();
        for i in 0..1000u32 {
            sroot = db
                .state_store
                .set(sroot, format!("key_{i:05}").as_bytes(), b"v")
                .unwrap();
        }
        let proof = db.state_store.proof(sroot, b"key_00042").unwrap();
        let proof_bytes = to_cbor(&proof).unwrap().len();

        // Warm: caches populated by the writes above.
        let start = Instant::now();
        for _ in 0..1000 {
            assert!(db.state_store.verify_proof(sroot, b"key_00042", &proof));
        }
        let warm = start.elapsed() / 1000;

        // Cold: a brand-new handle, so node/manifest caches start empty. Each
        // iteration reopens to keep the first-touch cost in the measurement.
        let start = Instant::now();
        let reps = 200;
        for _ in 0..reps {
            let fresh = Database::open(&root).unwrap();
            assert!(fresh.state_store.verify_proof(sroot, b"key_00042", &proof));
        }
        let cold = start.elapsed() / reps;
        eprintln!(
            "[q3] state proof ({proof_bytes} B, 1000 keys): warm verify {warm:?}, \
             cold verify (reopened db) {cold:?}"
        );
    }

    let mut group = c.benchmark_group("q3_auditor_verify");
    for (r, path, _, _) in &sizes {
        group.bench_function(format!("in_process_R={r}"), |b| {
            b.iter(|| audit::verify_bundle(path, None, false).unwrap())
        });
    }
    group.finish();
}

// ---------------------------------------------------------------- Q5
// BM25 collection statistics are segment-global: document frequency and
// collection size are computed over every chunk, including chunks the caller
// is forbidden to see. Measure what a tenant can infer from its own scores.

fn q5_idf_leakage(_c: &mut Criterion) {
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

    // One probe document owned by the attacker, containing the probe term.
    let probe = |i: usize, text: &str, meta: ChunkMetadata| ChunkInput {
        chunk_hash: hash_typed(b"q5:", format!("{i}").as_bytes()),
        text: text.to_string(),
        embedding: None,
        meta: Some(meta),
    };

    // Historical: with segment-global collection statistics the attacker's own
    // score was strictly monotone in the hidden count, so inverting BM25 gave
    // exact recovery of another tenant's per-term document frequency. Scoring
    // statistics are now partition-scoped; this measures that the channel is
    // closed rather than merely narrowed.
    eprintln!("[q5] attacker sees ONLY its own document; victim docs are filtered pre-scoring");
    let mut observed = Vec::new();
    for victim_docs in [0usize, 1, 2, 5, 10, 25, 50, 100, 250, 500] {
        for (label, victim_text) in [
            ("with-term", "secret probe term"),
            ("no-term", "unrelated filler words"),
        ] {
            let mut inputs = vec![probe(0, "secret probe term", mine.clone())];
            for j in 0..victim_docs {
                inputs.push(probe(1000 + j, victim_text, theirs.clone()));
            }
            let seg = IndexSegment::build(vec![], inputs);
            let hits = seg.bm25("probe", 10, &filter);
            assert_eq!(hits.len(), 1, "filter must hide every victim document");
            observed.push((victim_docs, label, hits[0].score));
        }
    }

    let distinct: std::collections::BTreeSet<u32> =
        observed.iter().map(|(_, _, s)| s.to_bits()).collect();
    for (n, label, score) in &observed {
        eprintln!(
            "[q5]   hidden victim docs = {n:>4} ({label:>9}) -> attacker's score = {score:.9}"
        );
    }
    eprintln!(
        "[q5] {} probes -> {} distinct observable score(s); 1 means the hidden \
         corpus is unobservable",
        observed.len(),
        distinct.len()
    );
    assert_eq!(
        distinct.len(),
        1,
        "cross-tenant statistics channel is open: the attacker's own score \
         varies with documents it cannot see"
    );

    // A term occurring only in hidden documents must look exactly like a term
    // that does not occur at all.
    let mut inputs = vec![probe(0, "alpha", mine.clone())];
    inputs.push(probe(9000, "confidential", theirs.clone()));
    let seg = IndexSegment::build(vec![], inputs);
    assert!(seg.bm25("confidential", 10, &filter).is_empty());
    assert!(seg.bm25("nonexistentword", 10, &filter).is_empty());
    eprintln!(
        "[q5] a term present only in hidden documents is indistinguishable from an absent one"
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = q2_checkpoint_chain, q3_q4_auditor, q5_idf_leakage
}
criterion_main!(benches);
