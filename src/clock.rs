use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

/// Seconds since the Unix epoch. Returns an error rather than panicking when
/// the system clock is set before 1970-01-01 — realistic on misconfigured
/// embedded targets, and the callers (commit, manifest, index, db config)
/// already propagate `Result`.
pub fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow!("system clock is set before unix epoch: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_is_positive_and_monotonic_within_call() {
        let a = now_unix().unwrap();
        let b = now_unix().unwrap();
        assert!(a > 0);
        assert!(b >= a);
    }
}
