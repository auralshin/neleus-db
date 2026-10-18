//! Runs one operation `n` times for benches/tools/sync-count.sh, which
//! preloads a library that counts durability syscalls. Operations: `state`,
//! `search` (neleus in `full` mode), `sqlite-wal`, `sqlite-rollback`
//! (`synchronous=FULL`, `fullfsync=ON`).

use neleus_db::Database;
use neleus_db::engine::{Engine, SearchFilter, SearchQuery};
use neleus_db::manifest::{ChunkManifest, ChunkingSpec, MANIFEST_SCHEMA_VERSION};

fn neleus(root: &std::path::Path) -> Engine {
    Database::init(root).unwrap();
    let cfg_path = root.join("meta").join("config.json");
    let mut cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg["durability"] = std::env::var("SYNC_COUNT_DURABILITY")
        .unwrap_or("full".into())
        .into();
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    Engine::open(root).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (op, n): (&str, usize) = (&args[1], args[2].parse().unwrap());
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("db");
    match op {
        "state" => {
            let engine = neleus(&root);
            engine
                .db()
                .state_set_at_head("main", b"warm", b"v")
                .unwrap();
            for i in 0..n {
                engine
                    .db()
                    .state_set_at_head("main", format!("k{i}").as_bytes(), b"payload-0123456789")
                    .unwrap();
            }
        }
        "search" => {
            let engine = neleus(&root);
            engine
                .put_document(
                    "main",
                    "kb",
                    b"vector retrieval latency corpus for counting syncs",
                    ChunkingSpec {
                        method: "fixed".into(),
                        chunk_size: 64,
                        overlap: 0,
                    },
                    None,
                    "bench",
                )
                .unwrap();
            let search = || {
                engine
                    .search(
                        "main",
                        None,
                        SearchQuery::Semantic("retrieval latency"),
                        10,
                        &SearchFilter::default(),
                        None,
                    )
                    .unwrap()
            };
            search();
            for _ in 0..n {
                search();
            }
        }
        "commit-empty" | "commit-manifest" | "commit-objects" => {
            let engine = neleus(&root);
            let db = engine.db();
            db.create_commit_at_head("main", "bench", "warm", vec![])
                .unwrap();
            let start = std::time::Instant::now();
            for i in 0..n {
                let manifests = if op != "commit-empty" {
                    let chunk = ChunkManifest {
                        schema_version: MANIFEST_SCHEMA_VERSION,
                        chunk_text: db.blob_store.put(format!("chunk {i}").as_bytes()).unwrap(),
                        start: 0,
                        end: 1,
                        embedding: None,
                        metadata: None,
                    };
                    vec![db.manifest_store.put_manifest(&chunk).unwrap()]
                } else {
                    vec![]
                };
                // commit-objects writes the same objects but indexes none.
                let listed = if op == "commit-objects" {
                    vec![]
                } else {
                    manifests
                };
                db.create_commit_at_head("main", "bench", "c", listed)
                    .unwrap();
            }
            if n > 0 {
                eprintln!("[time] {op} {:?}/op", start.elapsed() / n as u32);
            }
        }
        "sqlite-wal" | "sqlite-rollback" => {
            let conn = rusqlite::Connection::open(root.with_extension("sqlite")).unwrap();
            let mode = if op == "sqlite-wal" { "WAL" } else { "DELETE" };
            conn.pragma_update(None, "journal_mode", mode).unwrap();
            conn.pragma_update(None, "synchronous", "FULL").unwrap();
            conn.pragma_update(None, "fullfsync", true).unwrap();
            conn.execute_batch("CREATE TABLE kv (key BLOB PRIMARY KEY, value BLOB);")
                .unwrap();
            let mut stmt = conn
                .prepare("INSERT OR REPLACE INTO kv(key, value) VALUES (?1, ?2)")
                .unwrap();
            stmt.execute((b"warm".as_slice(), b"v".as_slice())).unwrap();
            for i in 0..n {
                stmt.execute((
                    format!("k{i}").into_bytes(),
                    b"payload-0123456789".as_slice(),
                ))
                .unwrap();
            }
        }
        other => panic!("unknown operation {other}"),
    }
}
