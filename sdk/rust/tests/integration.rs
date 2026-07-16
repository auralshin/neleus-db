//! End-to-end: start a real `neleus-db serve` in-process and drive the
//! client against it across every surface.

use std::time::Duration;

use neleus_client::{Client, DocOpts, SearchOpts};
use neleus_db::auth::{Role, add_key};
use neleus_db::server::{ServerConfig, ServerHandle, start};
use neleus_db::{Database, Engine};
use tempfile::TempDir;

struct Fixture {
    handle: Option<ServerHandle>,
    url: String,
    token: String,
    _tmp: TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown();
        }
    }
}

fn serve() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let token = add_key(&root, "test", Role::Admin, None).unwrap();
    let engine = Engine::open(&root).unwrap();
    let handle = start(
        engine,
        ServerConfig {
            addr: "127.0.0.1:0".into(),
            allow_remote: false,
            no_auth: false,
            cors_origin: None,
            bootstrap: false,
        },
    )
    .unwrap();
    let url = format!("http://{}", handle.addr);
    Fixture {
        handle: Some(handle),
        url,
        token,
        _tmp: tmp,
    }
}

fn client(f: &Fixture) -> Client {
    Client::with_timeout(&f.url, Some(f.token.clone()), Duration::from_secs(30))
}

#[test]
fn health_and_ingest_search_prove_verify() {
    let f = serve();
    let c = client(&f);

    let health = c.health().unwrap();
    assert_eq!(health["ok"], true);

    let doc = c
        .put_document(
            "main",
            "kb.md",
            "Rust agents need verifiable per-jurisdiction audit trails for regulated retrieval.",
            DocOpts::default(),
        )
        .unwrap();
    assert!(doc["commit"].is_string());

    let res = c
        .search(
            "main",
            SearchOpts {
                query: Some("verifiable audit trails".into()),
                mode: Some("semantic".into()),
                audit: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!res.hits.is_empty());
    assert!(res.audit_manifest.is_some());

    let proof = c.prove(&res.commit, &res.hits[0].chunk, true).unwrap();
    let verdict = c.verify(&proof).unwrap();
    assert!(verdict.valid, "{verdict:?}");
    assert_eq!(verdict.anchor.as_deref(), Some("doc"));
}

#[test]
fn audit_surfaces() {
    let f = serve();
    let c = client(&f);

    c.put_document("main", "kb", "auditable policy corpus", DocOpts::default())
        .unwrap();
    let res = c
        .search(
            "main",
            SearchOpts {
                query: Some("policy".into()),
                mode: Some("semantic".into()),
                audit: true,
                ..Default::default()
            },
        )
        .unwrap();
    let qm = res.audit_manifest.unwrap();
    c.commit("main", "audit", &[qm]).unwrap();
    c.checkpoint("main").unwrap();

    // Export bundle verifies offline through the engine's verifier.
    let bundle = c.export_bundle("main", None, None).unwrap();
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("dl.nelaudit");
    std::fs::write(&path, &bundle).unwrap();
    let report = neleus_db::audit::verify_bundle(&path, None, false).unwrap();
    assert_eq!(report.retrievals, 1);
}

#[test]
fn run_capture_records_a_manifest() {
    let f = serve();
    let c = client(&f);

    let out = c
        .run("anthropic", "claude-sonnet-4-6")
        .head("main")
        .agent_id("reviewer-v1")
        .prompt("does this policy allow X?")
        .output(b"yes, under section 4")
        .unwrap()
        .commit()
        .unwrap();
    assert!(out["manifest"].is_string());
    assert!(out["commit"].is_string());
}

#[test]
fn sessions_round_trip() {
    let f = serve();
    let c = client(&f);

    c.session_append("main", "s1", "hello", Some("user"), Some(3600))
        .unwrap();
    let turns = c.session_list("main", "s1").unwrap();
    assert_eq!(turns["turns"].as_array().unwrap().len(), 1);
}

#[test]
fn bad_token_is_rejected() {
    let f = serve();
    let c = Client::new(&f.url, Some("nlk_wrong".into()));
    let err = c.health().unwrap_err();
    assert!(matches!(err, neleus_client::Error::Status { status: 401, .. }));
}
