//! End-to-end: policy-as-code enforcement over the real HTTP server.
//!
//! Seeds a policy set, drives writes through `/v1/*`, and asserts that
//! `enforce`-mode rules return 403, that violations land in the tamper-evident
//! event log, and that a compliant write passes. Exercises the public API the
//! way an operator/SDK would.

use neleus_db::auth::{Role, add_key};
use neleus_db::server::{ServerConfig, ServerHandle, start};
use neleus_db::sync::http_request;
use neleus_db::{Database, Engine};
use tempfile::TempDir;

fn boot(tmp: &TempDir) -> (ServerHandle, String, String) {
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let token = add_key(&root, "admin", Role::Admin, None).unwrap();
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
    (handle, url, token)
}

fn post(url: &str, path: &str, token: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    http_request(url, "POST", path, Some(token), &[], Some(body))
}

#[test]
fn enforce_blocks_writes_records_violations_and_chain_verifies() {
    let tmp = TempDir::new().unwrap();
    let (handle, url, token) = boot(&tmp);

    // 1. Apply policy-as-code: encryption + provenance, both enforce.
    post(
        &url,
        "/v1/policy",
        &token,
        br#"{"policies":[
            {"id":"enc","rule":{"kind":"require-encryption-at-rest"},"mode":"enforce"},
            {"id":"prov","heads":["*"],"rule":{"kind":"require-provenance"},"mode":"enforce"}
        ]}"#,
    )
    .expect("apply policy set");

    // 2. A document write violates encryption-at-rest -> 403, naming the policy.
    let err = post(
        &url,
        "/v1/documents",
        &token,
        br#"{"head":"main","source":"kb","text":"x"}"#,
    )
    .expect_err("write must be blocked")
    .to_string();
    assert!(err.contains("403"), "expected 403, got: {err}");
    assert!(
        err.contains("policy 'enc'"),
        "block must name the policy: {err}"
    );

    // 3. Relax encryption to monitor; a run WITH provenance now commits.
    post(
        &url,
        "/v1/policy",
        &token,
        br#"{"policies":[
            {"id":"enc","rule":{"kind":"require-encryption-at-rest"},"mode":"monitor"},
            {"id":"prov","heads":["*"],"rule":{"kind":"require-provenance"},"mode":"enforce"}
        ]}"#,
    )
    .unwrap();
    let ok = post(
        &url,
        "/v1/runs",
        &token,
        br#"{"head":"main","model":"m","provider":"openai"}"#,
    )
    .expect("provenance run must pass");
    assert!(
        String::from_utf8_lossy(&ok).contains("commit"),
        "run should return a commit"
    );

    // 4. A run WITHOUT provenance is still blocked by the enforce rule.
    let err = post(&url, "/v1/runs", &token, br#"{"head":"main","model":"m"}"#)
        .expect_err("run without provenance must be blocked")
        .to_string();
    assert!(
        err.contains("403") && err.contains("policy 'prov'"),
        "got: {err}"
    );

    // 5. Violations are visible over HTTP, for both rules that fired.
    let events = http_request(&url, "GET", "/v1/events", Some(&token), &[], None).unwrap();
    let feed = String::from_utf8_lossy(&events);
    assert!(feed.contains("policy.violation"), "event feed: {feed}");
    assert!(
        feed.contains("\"enc\""),
        "encryption violation missing: {feed}"
    );
    assert!(
        feed.contains("\"prov\""),
        "provenance violation missing: {feed}"
    );

    // 6. The on-disk event chain is intact (tamper-evident).
    let count = neleus_db::events::verify(&tmp.path().join("db")).unwrap();
    assert!(count >= 2, "expected >=2 recorded violations, got {count}");

    handle.shutdown();
}

#[test]
fn monitor_surfaces_evaluation_and_event_cursor() {
    let tmp = TempDir::new().unwrap();
    let (handle, url, token) = boot(&tmp);

    post(
        &url,
        "/v1/policy",
        &token,
        br#"{"policies":[{"id":"enc","rule":{"kind":"require-encryption-at-rest"},"mode":"enforce"}]}"#,
    )
    .unwrap();

    // Live evaluation surfaces the failing global rule.
    let report =
        String::from_utf8(post(&url, "/v1/policy/evaluate", &token, b"{}").unwrap()).unwrap();
    assert!(
        report.contains("\"policy_id\":\"enc\""),
        "evaluate report: {report}"
    );
    assert!(
        report.contains("\"status\":\"fail\""),
        "evaluate report: {report}"
    );

    // A blocked write lands in the live feed.
    let _ = post(
        &url,
        "/v1/documents",
        &token,
        br#"{"head":"main","source":"k","text":"x"}"#,
    );
    let feed = http_request(&url, "GET", "/v1/events", Some(&token), &[], None).unwrap();
    assert!(String::from_utf8_lossy(&feed).contains("policy.violation"));

    // The `since` cursor filters out already-seen events; `wait` long-polls and
    // returns empty when nothing newer arrives.
    let caught_up = http_request(
        &url,
        "GET",
        "/v1/events?since=100000&wait=1",
        Some(&token),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&caught_up).trim(),
        r#"{"events":[]}"#
    );

    handle.shutdown();
}

#[test]
fn monitor_mode_records_but_never_blocks() {
    let tmp = TempDir::new().unwrap();
    let (handle, url, token) = boot(&tmp);

    // Per-write rule in monitor mode: the write proceeds, violation recorded.
    post(
        &url,
        "/v1/policy",
        &token,
        br#"{"policies":[{"id":"prov","heads":["*"],"rule":{"kind":"require-provenance"},"mode":"monitor"}]}"#,
    )
    .unwrap();

    // A run with no provenance still commits (monitor never blocks)...
    let ok = post(&url, "/v1/runs", &token, br#"{"head":"main","model":"m"}"#)
        .expect("monitor mode must not block the write");
    assert!(String::from_utf8_lossy(&ok).contains("commit"));

    // ...but the violation was recorded all the same.
    let events = http_request(&url, "GET", "/v1/events", Some(&token), &[], None).unwrap();
    assert!(String::from_utf8_lossy(&events).contains("\"prov\""));

    handle.shutdown();
}
