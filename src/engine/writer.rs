//! Write coalescer: individual writes park in a queue for up to a small
//! window (or until the batch fills), then flush together as ONE segment +
//! ONE ref CAS. Callers block until their batch commits, so semantics match
//! a direct write — but N concurrent writers share one commit instead of
//! paying the full write path N times.

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use crate::db::Database;
use crate::state::StateRoot;

pub const DEFAULT_MAX_BATCH: usize = 256;
pub const DEFAULT_WINDOW: Duration = Duration::from_micros(500);

enum Op {
    Set(Vec<u8>, Vec<u8>),
    Del(Vec<u8>),
}

struct Request {
    op: Op,
    // anyhow::Error is not Clone; the whole batch shares one outcome.
    reply: mpsc::SyncSender<Result<StateRoot, String>>,
}

pub struct WriteCoalescer {
    tx: Option<mpsc::Sender<Request>>,
    join: Option<JoinHandle<()>>,
}

impl WriteCoalescer {
    /// Spawn a committer for `head`. Writes flush when `max_batch` requests
    /// are queued or `window` elapses after the first, whichever is sooner.
    pub fn new(db: Database, head: &str, max_batch: usize, window: Duration) -> Self {
        let (tx, rx) = mpsc::channel::<Request>();
        let head = head.to_string();
        let join = std::thread::spawn(move || committer(db, &head, rx, max_batch.max(1), window));
        Self {
            tx: Some(tx),
            join: Some(join),
        }
    }

    /// Blocks until the batch containing this write commits. Returns the
    /// state root after that batch.
    pub fn set(&self, key: &[u8], value: &[u8]) -> Result<StateRoot> {
        self.submit(Op::Set(key.to_vec(), value.to_vec()))
    }

    pub fn delete(&self, key: &[u8]) -> Result<StateRoot> {
        self.submit(Op::Del(key.to_vec()))
    }

    fn submit(&self, op: Op) -> Result<StateRoot> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .ok_or_else(|| anyhow!("coalescer is shut down"))?
            .send(Request {
                op,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("coalescer thread exited"))?;
        reply_rx
            .recv()
            .map_err(|_| anyhow!("coalescer thread exited before replying"))?
            .map_err(|e| anyhow!(e))
    }
}

impl Drop for WriteCoalescer {
    fn drop(&mut self) {
        drop(self.tx.take()); // disconnects; committer drains and exits
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn committer(
    db: Database,
    head: &str,
    rx: mpsc::Receiver<Request>,
    max_batch: usize,
    window: Duration,
) {
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        // Drain whatever is already queued before arming any timer.
        while batch.len() < max_batch {
            match rx.try_recv() {
                Ok(req) => batch.push(req),
                Err(_) => break,
            }
        }
        // Adaptive window: a lone writer gets a token wait (no regression vs
        // the direct path); concurrent arrivals extend to the full window so
        // amortization kicks in.
        let wait = if batch.len() == 1 {
            window / 10
        } else {
            window
        };
        let deadline = Instant::now() + wait;
        while batch.len() < max_batch {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(req) => batch.push(req),
                Err(_) => break, // timeout or disconnect: flush what we have
            }
        }

        let ops: Vec<(&[u8], Option<&[u8]>)> = batch
            .iter()
            .map(|r| match &r.op {
                Op::Set(k, v) => (k.as_slice(), Some(v.as_slice())),
                Op::Del(k) => (k.as_slice(), None),
            })
            .collect();

        match db.state_write_many_at_head(head, &ops) {
            Ok(root) => {
                for req in &batch {
                    let _ = req.reply.send(Ok(root));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                for req in &batch {
                    let _ = req.reply.send(Err(msg.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
    fn coalesced_writes_land_and_read_back() {
        let (_tmp, db) = test_db();
        let writer = WriteCoalescer::new(db.clone(), "main", 64, Duration::from_micros(200));
        let root = writer.set(b"a", b"1").unwrap();
        assert_eq!(db.state_store.get(root, b"a").unwrap(), Some(b"1".to_vec()));

        let root = writer.delete(b"a").unwrap();
        assert_eq!(db.state_store.get(root, b"a").unwrap(), None);
    }

    #[test]
    fn concurrent_writers_share_batches() {
        let (_tmp, db) = test_db();
        let writer = Arc::new(WriteCoalescer::new(
            db.clone(),
            "main",
            DEFAULT_MAX_BATCH,
            Duration::from_millis(2),
        ));

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let writer = Arc::clone(&writer);
                std::thread::spawn(move || {
                    for i in 0..50 {
                        writer.set(format!("k-{t}-{i}").as_bytes(), b"v").unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let root = db.resolve_state_root("main").unwrap();
        for t in 0..8 {
            for i in 0..50 {
                assert_eq!(
                    db.state_store
                        .get(root, format!("k-{t}-{i}").as_bytes())
                        .unwrap(),
                    Some(b"v".to_vec()),
                    "lost write k-{t}-{i}"
                );
            }
        }
    }

    #[test]
    fn drop_flushes_pending_and_joins() {
        let (_tmp, db) = test_db();
        {
            let writer = WriteCoalescer::new(db.clone(), "main", 64, Duration::from_millis(5));
            writer.set(b"k", b"v").unwrap();
        } // drop joins the committer
        let root = db.resolve_state_root("main").unwrap();
        assert_eq!(db.state_store.get(root, b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn simultaneous_writers_share_one_commit_and_last_wins() {
        let (_tmp, db) = test_db();
        let writer = Arc::new(WriteCoalescer::new(
            db.clone(),
            "main",
            64,
            Duration::from_millis(100),
        ));

        // All writers release together; the committer's token wait (window/10)
        // is far longer than the barrier skew, so they share one batch.
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let roots: Vec<StateRoot> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|t| {
                    let writer = Arc::clone(&writer);
                    let barrier = Arc::clone(&barrier);
                    s.spawn(move || {
                        barrier.wait();
                        writer.set(format!("k-{t}").as_bytes(), b"v").unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(
            roots.iter().all(|r| *r == roots[0]),
            "simultaneous writers must share one batch commit"
        );

        // Ordering: a later write to the same key wins regardless of batching.
        writer.set(b"k", b"first").unwrap();
        writer.set(b"k", b"second").unwrap();
        let root = db.resolve_state_root("main").unwrap();
        assert_eq!(
            db.state_store.get(root, b"k").unwrap(),
            Some(b"second".to_vec())
        );
    }
}
