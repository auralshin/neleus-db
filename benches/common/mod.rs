//! Bench database setup. `NELEUS_BENCH_DURABILITY` (os|full) and
//! `NELEUS_BENCH_ENCRYPT=1` set the config from init, as a deployment would.

// Each bench crate compiles its own copy and uses a subset.
#![allow(dead_code)]

use std::path::Path;

use neleus_db::Database;

pub fn init_db(root: &Path) {
    // Encryption must be configured before first open, so take a valid config
    // from a throwaway init, edit it, and place it before initializing `root`.
    let seed = root.with_extension("seed");
    Database::init(&seed).unwrap();
    let mut cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(seed.join("meta").join("config.json")).unwrap())
            .unwrap();
    std::fs::remove_dir_all(&seed).unwrap();
    if let Ok(mode) = std::env::var("NELEUS_BENCH_DURABILITY") {
        cfg["durability"] = mode.into();
    }
    if std::env::var("NELEUS_BENCH_ENCRYPT").is_ok_and(|v| v == "1") {
        cfg["encryption"] = serde_json::json!({"enabled": true, "algorithm": "aes-256-gcm"});
        // SAFETY: set before any benchmark thread reads the environment.
        unsafe { std::env::set_var("NELEUS_DB_ENCRYPTION_PASSWORD", "bench-password") };
    }
    std::fs::create_dir_all(root.join("meta")).unwrap();
    std::fs::write(
        root.join("meta").join("config.json"),
        serde_json::to_vec_pretty(&cfg).unwrap(),
    )
    .unwrap();
    Database::init(root).unwrap();
}

/// `NELEUS_BENCH_WRITES_ONLY=1`: build only what the write and recorded-search
/// groups need, via the cheapest path, so a durable run does not spend its
/// time on setup it does not measure.
pub fn writes_only() -> bool {
    std::env::var("NELEUS_BENCH_WRITES_ONLY").is_ok_and(|v| v == "1")
}
