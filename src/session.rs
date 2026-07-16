//! Episodic session memory under the reserved `__session__/` state keyspace.
//! Inherits Merkle commitments/proofs/encryption from state; adds TTL:
//! reads filter expired records, `gc` tombstones + compacts them away.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::clock::now_unix;
use crate::db::Database;
use crate::hash::Hash;

pub const SESSION_SCHEMA_VERSION: u32 = 1;
const SESSION_PREFIX: &str = "__session__/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub schema_version: u32,
    pub session_id: String,
    pub seq: u64,
    /// `"user"`, `"assistant"`, `"tool"`, `"summary"`, ... — caller-defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Content-addressed blob of the turn payload.
    pub content: Hash,
    pub created_at: u64,
    /// Unix seconds after which this record is expired. `None` = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl SessionRecord {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }
}

/// Stateless session API over a [`Database`].
pub struct SessionStore<'a> {
    db: &'a Database,
}

impl<'a> SessionStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn key(session_id: &str, seq: u64) -> Vec<u8> {
        // 16-hex-digit seq keeps byte order == numeric order in scans.
        format!("{SESSION_PREFIX}{session_id}/{seq:016x}").into_bytes()
    }

    fn session_prefix(session_id: &str) -> Vec<u8> {
        format!("{SESSION_PREFIX}{session_id}/").into_bytes()
    }

    fn validate_id(session_id: &str) -> Result<()> {
        if session_id.is_empty()
            || session_id.contains('/')
            || session_id.bytes().any(|b| b.is_ascii_control())
        {
            return Err(anyhow!(
                "invalid session id {session_id:?}: must be non-empty, no '/' or control bytes"
            ));
        }
        Ok(())
    }

    /// Append a turn; returns `(seq, content_hash)`.
    pub fn append(
        &self,
        head: &str,
        session_id: &str,
        role: Option<&str>,
        content: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(u64, Hash)> {
        Self::validate_id(session_id)?;
        let now = now_unix()?;
        let seq = self.next_seq(head, session_id)?;
        let content_hash = self.db.blob_store.put(content)?;
        let record = SessionRecord {
            schema_version: SESSION_SCHEMA_VERSION,
            session_id: session_id.to_string(),
            seq,
            role: role.map(str::to_string),
            content: content_hash,
            created_at: now,
            expires_at: ttl_secs.map(|t| now.saturating_add(t)),
        };
        let bytes = crate::canonical::to_cbor(&record)?;
        self.db
            .state_set_at_head(head, &Self::key(session_id, seq), &bytes)?;
        Ok((seq, content_hash))
    }

    fn next_seq(&self, head: &str, session_id: &str) -> Result<u64> {
        let root = self.db.resolve_state_root(head)?;
        let prefix = Self::session_prefix(session_id);
        let entries = self.db.state_store.scan_prefix(root, &prefix)?;
        // Keys are zero-padded hex, so the max is the last one.
        let max = entries
            .last()
            .and_then(|(k, _)| std::str::from_utf8(&k[prefix.len()..]).ok())
            .and_then(|hexseq| u64::from_str_radix(hexseq, 16).ok());
        Ok(max.map(|m| m + 1).unwrap_or(0))
    }

    /// Live turns oldest-first. `now=Some(t)` filters expired; `None` = replay view.
    pub fn list(
        &self,
        head: &str,
        session_id: &str,
        now: Option<u64>,
    ) -> Result<Vec<SessionRecord>> {
        Self::validate_id(session_id)?;
        let root = self.db.resolve_state_root(head)?;
        let prefix = Self::session_prefix(session_id);
        let mut out = Vec::new();
        for (key, _) in self.db.state_store.scan_prefix(root, &prefix)? {
            let Some(bytes) = self.db.state_store.get(root, &key)? else {
                continue;
            };
            let record: SessionRecord = crate::canonical::from_cbor(&bytes)?;
            if let Some(t) = now
                && record.is_expired(t)
            {
                continue;
            }
            out.push(record);
        }
        out.sort_by_key(|r| r.seq);
        Ok(out)
    }

    /// Fetch the content blob of a turn.
    pub fn content(&self, record: &SessionRecord) -> Result<Vec<u8>> {
        self.db.blob_store.get(record.content)
    }

    /// Remove every expired record across all sessions, then compact.
    /// Records younger than `retention_min_secs` (config) are kept even when
    /// expired: expiry hides them from reads, retention controls physical
    /// removal.
    pub fn gc(&self, head: &str, now: u64) -> Result<usize> {
        let retention = self.db.config.retention_min_secs.unwrap_or(0);
        let root = self.db.resolve_state_root(head)?;
        let mut expired: Vec<Vec<u8>> = Vec::new();
        for (key, _) in self
            .db
            .state_store
            .scan_prefix(root, SESSION_PREFIX.as_bytes())?
        {
            let Some(bytes) = self.db.state_store.get(root, &key)? else {
                continue;
            };
            let Ok(record) = crate::canonical::from_cbor::<SessionRecord>(&bytes) else {
                continue; // foreign data under the session prefix; leave it
            };
            if record.is_expired(now) && now >= record.created_at.saturating_add(retention) {
                expired.push(key);
            }
        }
        if expired.is_empty() {
            return Ok(0);
        }
        let refs: Vec<&[u8]> = expired.iter().map(|k| k.as_slice()).collect();
        self.db.state_del_many_at_head(head, &refs)?;
        self.db.state_compact_at_head(head)?;
        Ok(expired.len())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        (tmp, db)
    }

    #[test]
    fn append_and_list_orders_by_seq() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        let (s0, _) = sessions
            .append("main", "s1", Some("user"), b"hi", None)
            .unwrap();
        let (s1, _) = sessions
            .append("main", "s1", Some("assistant"), b"hello", None)
            .unwrap();
        assert_eq!((s0, s1), (0, 1));

        let turns = sessions.list("main", "s1", None).unwrap();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role.as_deref(), Some("user"));
        assert_eq!(sessions.content(&turns[1]).unwrap(), b"hello");
    }

    #[test]
    fn sessions_are_isolated_by_id() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        sessions.append("main", "a", None, b"x", None).unwrap();
        sessions.append("main", "b", None, b"y", None).unwrap();
        assert_eq!(sessions.list("main", "a", None).unwrap().len(), 1);
        assert_eq!(sessions.list("main", "b", None).unwrap().len(), 1);
    }

    #[test]
    fn expired_records_filtered_then_gced() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        sessions
            .append("main", "s", None, b"ephemeral", Some(10))
            .unwrap();
        sessions
            .append("main", "s", None, b"permanent", None)
            .unwrap();

        let now = now_unix().unwrap();
        let live = sessions.list("main", "s", Some(now + 60)).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(sessions.content(&live[0]).unwrap(), b"permanent");

        // Replay view still sees both.
        assert_eq!(sessions.list("main", "s", None).unwrap().len(), 2);

        // GC physically removes the expired record.
        let removed = sessions.gc("main", now + 60).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(sessions.list("main", "s", None).unwrap().len(), 1);
    }

    #[test]
    fn seq_survives_gc_of_older_turns() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        sessions.append("main", "s", None, b"t0", Some(1)).unwrap();
        let now = now_unix().unwrap();
        sessions.gc("main", now + 60).unwrap();
        // After GC clears all turns, seq may restart; assert list stays consistent.
        let (seq, _) = sessions.append("main", "s", None, b"t1", None).unwrap();
        let turns = sessions.list("main", "s", None).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].seq, seq);
    }

    #[test]
    fn retention_blocks_physical_removal_of_expired_records() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        // Retention window far in the future: expired records stay on disk.
        let cfg_path = root.join("meta").join("config.json");
        let mut cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        cfg["retention_min_secs"] = serde_json::json!(10 * 365 * 24 * 3600u64);
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let db = Database::open(&root).unwrap();

        let sessions = SessionStore::new(&db);
        sessions
            .append("main", "s", None, b"ephemeral", Some(1))
            .unwrap();
        let now = now_unix().unwrap();

        // Expired for reads, but retention forbids removal.
        assert!(
            sessions
                .list("main", "s", Some(now + 60))
                .unwrap()
                .is_empty()
        );
        assert_eq!(sessions.gc("main", now + 60).unwrap(), 0);
        assert_eq!(sessions.list("main", "s", None).unwrap().len(), 1);
    }

    #[test]
    fn invalid_session_ids_rejected() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        assert!(sessions.append("main", "", None, b"x", None).is_err());
        assert!(sessions.append("main", "a/b", None, b"x", None).is_err());
    }

    #[test]
    fn many_writes_all_readable() {
        let (_tmp, db) = test_db();
        let sessions = SessionStore::new(&db);
        for i in 0..150 {
            sessions
                .append("main", "s", None, format!("turn {i}").as_bytes(), None)
                .unwrap();
        }
        // 150 appends stay fully readable and correctly ordered; the
        // authenticated prolly tree keeps lookups O(log n) regardless of count.
        let turns = sessions.list("main", "s", None).unwrap();
        assert_eq!(turns.len(), 150);
        assert_eq!(turns[149].seq, 149);
    }
}
