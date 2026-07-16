//! CLI dispatch coverage: drives the `neleus-db` binary through the command
//! groups that don't need a server, exercising main.rs end to end.

use std::process::{Command, Output};

use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_neleus-db")
}

fn ok(args: &[&str]) -> Output {
    let out = Command::new(bin()).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "command {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn cli_command_dispatch_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let dbs = db.to_str().unwrap();

    ok(&["db", "init", dbs]);

    // ed25519 key; capture its public key from the JSON output (std string parse).
    let keyf = tmp.path().join("k.key");
    let keys = keyf.to_str().unwrap();
    let kout = ok(&["--db", dbs, "key", "generate", "--out", keys, "--json"]);
    let pubhex = String::from_utf8_lossy(&kout.stdout)
        .split("\"public_key\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("public_key in output")
        .to_string();
    assert_eq!(pubhex.len(), 64);

    // policy-as-code: apply, list, evaluate, remove-missing (no-op).
    let polf = tmp.path().join("p.json");
    std::fs::write(
        &polf,
        br#"{"policies":[{"id":"enc","rule":{"kind":"require-encryption-at-rest"},"mode":"monitor"}]}"#,
    )
    .unwrap();
    ok(&["--db", dbs, "policy", "set", polf.to_str().unwrap()]);
    ok(&["--db", dbs, "policy", "list"]);
    ok(&["--db", dbs, "policy", "eval"]);
    ok(&["--db", dbs, "policy", "rm", "--id", "does-not-exist"]);

    // erasure: signed request, list shows the subject, verify the signature.
    ok(&[
        "--db",
        dbs,
        "erasure",
        "request",
        "--subject",
        "u-1",
        "--sign-key",
        keys,
    ]);
    let list = ok(&["--db", dbs, "erasure", "list"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("u-1"));
    ok(&["--db", dbs, "erasure", "verify", "--public-key", &pubhex]);

    // event log: the erasure appended an event; the chain verifies.
    ok(&["--db", dbs, "events", "list"]);
    ok(&["--db", dbs, "events", "verify"]);
}

fn json_str(out: &Output, key: &str) -> String {
    String::from_utf8_lossy(&out.stdout)
        .split(&format!("\"{key}\": \""))
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("key {key} missing in output"))
        .to_string()
}

#[test]
fn cli_pipeline_ingest_search_prove_audit() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let dbs = db.to_str().unwrap();
    let docf = tmp.path().join("doc.txt");
    std::fs::write(
        &docf,
        b"compliance policy reset daily; audit logs and governance matter",
    )
    .unwrap();

    ok(&["db", "init", dbs]);

    // ingest -> manifest, commit to a head, build the index.
    let put = ok(&[
        "--db",
        dbs,
        "manifest",
        "put-doc",
        "--source",
        "kb",
        "--file",
        docf.to_str().unwrap(),
        "--chunk-size",
        "24",
        "--json",
    ]);
    let mh = json_str(&put, "manifest_hash");
    ok(&[
        "--db",
        dbs,
        "commit",
        "new",
        "--head",
        "main",
        "--author",
        "tester",
        "--message",
        "ingest",
        "--manifest",
        &mh,
    ]);
    ok(&["--db", dbs, "index", "build", "--head", "main"]);
    ok(&["--db", dbs, "log", "main"]);

    // search, then prove a hit and verify it offline.
    let res = ok(&[
        "--db",
        dbs,
        "search",
        "hybrid",
        "--head",
        "main",
        "--query",
        "compliance",
        "--top-k",
        "2",
        "--json",
    ]);
    let chunk = json_str(&res, "chunk_hash");
    let proof = tmp.path().join("p.cbor");
    ok(&[
        "--db",
        dbs,
        "proof",
        "chunk",
        "--head",
        "main",
        "--chunk",
        &chunk,
        "--include-content",
        "--out",
        proof.to_str().unwrap(),
    ]);
    ok(&[
        "--db",
        dbs,
        "proof",
        "verify-chunk",
        proof.to_str().unwrap(),
    ]);

    // transparency chain.
    ok(&["--db", dbs, "checkpoint", "new", "--head", "main"]);
    ok(&["--db", dbs, "checkpoint", "verify", "--head", "main"]);

    // keyed state.
    let valf = tmp.path().join("v.bin");
    std::fs::write(&valf, b"value-bytes").unwrap();
    ok(&[
        "--db",
        dbs,
        "state",
        "set",
        "main",
        "userkey",
        valf.to_str().unwrap(),
    ]);
    ok(&["--db", dbs, "state", "get", "main", "userkey"]);

    // audit surface.
    ok(&["--db", dbs, "audit", "log", "--head", "main"]);
}

#[test]
fn cli_storage_session_audit_surfaces() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("db");
    let dbs = db.to_str().unwrap();
    ok(&["db", "init", dbs]);

    // blob put/get roundtrip + object inspect.
    let bf = tmp.path().join("b.bin");
    std::fs::write(&bf, b"raw blob bytes").unwrap();
    let bput = ok(&["--db", dbs, "blob", "put", bf.to_str().unwrap(), "--json"]);
    let bhash = json_str(&bput, "hash");
    let bget = tmp.path().join("b.out");
    ok(&["--db", dbs, "blob", "get", &bhash, bget.to_str().unwrap()]);
    assert_eq!(std::fs::read(&bget).unwrap(), b"raw blob bytes");
    ok(&["--db", dbs, "object", "inspect", &bhash]);

    // run manifest -> commit to head main.
    let pf = tmp.path().join("prompt.txt");
    std::fs::write(&pf, b"summarize the policy").unwrap();
    let run = ok(&[
        "--db",
        dbs,
        "manifest",
        "put-run",
        "--model",
        "gpt-4",
        "--prompt-file",
        pf.to_str().unwrap(),
        "--provider",
        "openai",
        "--json",
    ]);
    let rh = json_str(&run, "manifest_hash");
    ok(&[
        "--db",
        dbs,
        "commit",
        "new",
        "--head",
        "main",
        "--author",
        "t",
        "--message",
        "run",
        "--manifest",
        &rh,
    ]);

    // session memory.
    ok(&[
        "--db",
        dbs,
        "session",
        "append",
        "--head",
        "main",
        "--session-id",
        "s1",
        "--role",
        "user",
        "--content",
        "hello",
    ]);
    ok(&[
        "--db",
        dbs,
        "session",
        "list",
        "--head",
        "main",
        "--session-id",
        "s1",
    ]);

    // pack / repack / packs / gc (dry-run).
    let pack = tmp.path().join("dump.pack");
    ok(&["--db", dbs, "db", "pack", pack.to_str().unwrap()]);
    ok(&["--db", dbs, "db", "packs"]);
    ok(&["--db", dbs, "db", "repack"]);
    ok(&["--db", dbs, "db", "gc"]);

    // audit bundle export + offline verify.
    let bundle = tmp.path().join("a.nelaudit");
    ok(&[
        "--db",
        dbs,
        "audit",
        "export",
        "--head",
        "main",
        "--out",
        bundle.to_str().unwrap(),
    ]);
    ok(&["--db", dbs, "audit", "verify", bundle.to_str().unwrap()]);
}

#[test]
fn cli_rejects_bad_invocation() {
    let out = Command::new(bin())
        .arg("definitely-not-a-command")
        .output()
        .unwrap();
    assert!(!out.status.success(), "unknown subcommand must fail");
}
