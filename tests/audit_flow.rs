//! End-to-end regression for the documented audit workflow:
//! `search --audit` -> `audit export` -> `neleus-verify`, and survival of
//! `db gc --prune`. Recording alone writes an unreferenced object, so this
//! flow silently produced empty bundles until retrieval records were
//! committed onto the head.

use std::time::Duration;

use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::manifest::ChunkingSpec;
use neleus_db::{Database, audit};
use tempfile::TempDir;

fn spec() -> ChunkingSpec {
    ChunkingSpec {
        method: "fixed".into(),
        chunk_size: 64,
        overlap: 0,
    }
}

#[test]
fn audited_search_is_exportable_verifiable_and_survives_gc() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document(
            "main",
            "kb",
            b"reset password policy text",
            spec(),
            None,
            "t",
        )
        .unwrap();

    let filter = SearchFilter::default();
    let hits = engine
        .search_semantic_unrecorded(commit, "password", 5, &filter)
        .unwrap();
    let qm = engine
        .record_query_at_head(
            "main",
            commit,
            "semantic",
            Some("password"),
            None,
            5,
            &filter,
            Some("cli"),
            &hits,
        )
        .unwrap();

    let out = tmp.path().join("q.nelaudit");
    let summary = audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    assert_eq!(
        summary.retrievals, 1,
        "audited retrieval missing from the export"
    );

    let report = audit::verify_bundle(&out, None, false).unwrap();
    assert_eq!(report.retrievals, 1);

    // A recorded retrieval is reachable, so collection must not reclaim it.
    neleus_db::gc::gc(engine.db(), true, Duration::from_secs(0)).unwrap();
    assert!(
        engine.db().object_store.exists(qm),
        "gc reclaimed a committed audit record"
    );
    assert_eq!(
        audit::export(engine.db(), "main", 0, u64::MAX, &out, None)
            .unwrap()
            .retrievals,
        1,
        "audit trail did not survive gc"
    );
}

/// The bare primitive still produces an unreferenced object. Documenting that
/// here keeps the distinction from `record_query_at_head` honest.
#[test]
fn bare_record_query_is_not_exportable() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document("main", "kb", b"some corpus text", spec(), None, "t")
        .unwrap();
    let filter = SearchFilter::default();
    let hits = engine
        .search_semantic_unrecorded(commit, "corpus", 5, &filter)
        .unwrap();
    engine
        .record_query(
            commit,
            "semantic",
            Some("corpus"),
            None,
            5,
            &filter,
            None,
            &hits,
        )
        .unwrap();

    let out = tmp.path().join("q.nelaudit");
    assert_eq!(
        audit::export(engine.db(), "main", 0, u64::MAX, &out, None)
            .unwrap()
            .retrievals,
        0,
        "uncommitted records must not appear; use record_query_at_head"
    );
}

/// The point of sequencing: an operator that drops a record from the exported
/// window must be caught. Integrity checks alone cannot see an absence.
#[test]
fn withheld_retrieval_is_detected() {
    use std::io::Write;

    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document("main", "kb", b"alpha beta gamma corpus", spec(), None, "t")
        .unwrap();

    let filter = SearchFilter::default();
    for i in 0..4 {
        let hits = engine
            .search_semantic_unrecorded(commit, "corpus", 5, &filter)
            .unwrap();
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("corpus"),
                None,
                5,
                &filter,
                Some(&format!("agent-{i}")),
                &hits,
            )
            .unwrap();
    }

    let out = tmp.path().join("full.nelaudit");
    let report = {
        audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
        audit::verify_bundle(&out, None, false).unwrap()
    };
    assert_eq!(report.retrievals, 4);

    // Sequence numbers are contiguous and prev-links agree.
    let records = audit::collect(engine.db(), "main", 0, u64::MAX).unwrap();
    let mut seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![0, 1, 2, 3]);

    // Now forge a bundle with the middle record withheld. Every remaining
    // record still hashes correctly and is still reachable from the tip, so
    // only the sequence gap can reveal the omission.
    let raw = std::fs::read(&out).unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let dropped = records.iter().find(|r| r.seq == 2).unwrap();
    let kept: Vec<String> = records
        .iter()
        .filter(|r| r.seq != 2)
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    assert!(
        text.contains(&dropped.manifest),
        "record present pre-tamper"
    );

    let mut jsonl = kept.join("\n");
    jsonl.push('\n');
    let tampered = tmp.path().join("withheld.nelaudit");
    // Rebuild the bundle with a shortened retrievals.jsonl and a matching
    // meta count, so nothing but the gap is inconsistent.
    rebuild_bundle(&raw, &jsonl, kept.len(), &tampered);

    let err = audit::verify_bundle(&tampered, None, false)
        .expect_err("a withheld record must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("gap") || msg.contains("withheld"),
        "expected a gap diagnosis, got: {msg}"
    );
    let _ = std::io::stderr().flush();
}

/// Rewrite fields the verifier once ignored (`mode`, `top_k`,
/// `queried_commit`, and a returned chunk hash), leaving the sequence chain
/// contiguous and the footer recomputed. Only comparing every field against the
/// hash-bound QueryManifest catches this; the gap check never fires.
#[test]
fn rewritten_record_fields_are_rejected() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document("main", "kb", b"alpha beta gamma corpus", spec(), None, "t")
        .unwrap();

    let filter = SearchFilter::default();
    for i in 0..3 {
        let hits = engine
            .search_semantic_unrecorded(commit, "corpus", 5, &filter)
            .unwrap();
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("corpus"),
                None,
                5,
                &filter,
                Some(&format!("agent-{i}")),
                &hits,
            )
            .unwrap();
    }

    let out = tmp.path().join("full.nelaudit");
    audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    audit::verify_bundle(&out, None, false).expect("honest bundle verifies");

    let raw = std::fs::read(&out).unwrap();
    let records = audit::collect(engine.db(), "main", 0, u64::MAX).unwrap();
    let forged: Vec<String> = records
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap();
            if r.seq == 1 {
                v["mode"] = serde_json::json!("vector");
                v["top_k"] = serde_json::json!(999);
                v["queried_commit"] = serde_json::json!("00".repeat(32));
                if !r.hits.is_empty() {
                    v["hits"][0]["chunk"] = serde_json::json!("11".repeat(32));
                }
            }
            serde_json::to_string(&v).unwrap()
        })
        .collect();

    let mut jsonl = forged.join("\n");
    jsonl.push('\n');
    let tampered = tmp.path().join("rewritten.nelaudit");
    rebuild_bundle(&raw, &jsonl, records.len(), &tampered);

    let err = audit::verify_bundle(&tampered, None, false)
        .expect_err("rewritten record fields must be rejected");
    assert!(
        err.to_string().contains("disagrees with its manifest"),
        "expected a manifest-disagreement diagnosis, got: {err}"
    );
}

/// A time window is provably complete at both ends: the record before it and
/// the records linking it to the checkpoint's pin travel with the bundle, and
/// dropping either is rejected.
#[test]
fn window_exports_carry_their_edges() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document("main", "kb", b"alpha beta gamma corpus", spec(), None, "t")
        .unwrap();
    let filter = SearchFilter::default();
    let search = || {
        let hits = engine
            .search_semantic_unrecorded(commit, "corpus", 5, &filter)
            .unwrap();
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("corpus"),
                None,
                5,
                &filter,
                None,
                &hits,
            )
            .unwrap();
    };
    // Three one-second epochs: records 0-1, 2-3 (then a checkpoint), 4.
    search();
    search();
    std::thread::sleep(Duration::from_millis(1100));
    search();
    search();
    neleus_db::checkpoint::CheckpointStore::new(engine.db())
        .create("main", None)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    search();
    let times: Vec<u64> = {
        let mut r = audit::collect(engine.db(), "main", 0, u64::MAX).unwrap();
        r.sort_by_key(|r| r.seq);
        r.iter().map(|r| r.executed_at).collect()
    };
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let (t0, t1, t2) = (times[0], times[2], times[4]);
    assert!(t0 < t1 && t1 < t2);

    let verify = |from: u64, to: u64, drop: &str| {
        let out = tmp.path().join("w.nelaudit");
        audit::export(engine.db(), "main", from, to, &out, None).unwrap();
        let raw = std::fs::read(&out).unwrap();
        let has_edge = String::from_utf8_lossy(&raw).contains("edge/");
        let cut = tmp.path().join("cut.nelaudit");
        rebuild_without(&raw, None, drop, &cut);
        (has_edge, audit::verify_bundle(&cut, None, false))
    };
    // Middle window: needs the record before it; the pin is inside it.
    assert!(verify(t1, t1, "").1.is_ok());
    assert!(verify(t1, t1, "edge/").1.is_err());
    // Window before the pin: needs the records linking it to the pin.
    let (has_edge, ok) = verify(t0, t0, "");
    assert!(has_edge && ok.is_ok());
    assert!(verify(t0, t0, "edge/").1.is_err());
    // Window after the pin: only the record before it.
    assert!(verify(t2, t2, "").1.is_ok());
    assert!(verify(t2, t2, "edge/").1.is_err());
}

/// Re-emit a bundle with `retrievals.jsonl` replaced and `meta.json`'s count
/// adjusted, recomputing the integrity footer so only the sequence gap is wrong.
fn rebuild_bundle(raw: &[u8], jsonl: &str, count: usize, out: &std::path::Path) {
    rebuild_without(raw, Some((jsonl, count)), "", out);
}

/// Re-emit a bundle without entries named `drop*` (empty drops nothing),
/// optionally replacing the records, with a fresh integrity footer.
fn rebuild_without(raw: &[u8], records: Option<(&str, usize)>, drop: &str, out: &std::path::Path) {
    let mut p = 16usize;
    let n = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for _ in 0..n {
        let nl = u32::from_le_bytes(raw[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let name = String::from_utf8(raw[p..p + nl].to_vec()).unwrap();
        p += nl;
        let dl = u64::from_le_bytes(raw[p..p + 8].try_into().unwrap()) as usize;
        p += 8;
        let data = raw[p..p + dl].to_vec();
        p += dl;
        if !drop.is_empty() && name.starts_with(drop) {
            continue;
        }
        let data = match records {
            Some((jsonl, _)) if name == "retrievals.jsonl" => jsonl.as_bytes().to_vec(),
            Some((_, count)) if name == "meta.json" => {
                let mut v: serde_json::Value = serde_json::from_slice(&data).unwrap();
                v["retrievals"] = serde_json::json!(count);
                serde_json::to_vec_pretty(&v).unwrap()
            }
            _ => data,
        };
        entries.push((name, data));
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(b"NELAUDIT");
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, data) in &entries {
        buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
    }
    let footer = blake3::hash(&buf);
    buf.extend_from_slice(footer.as_bytes());
    std::fs::write(out, &buf).unwrap();
}
