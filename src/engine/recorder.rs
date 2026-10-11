//! Group commit for retrieval records: concurrent recorders on one head share
//! one commit. The first caller in becomes the leader and commits what is
//! queued while the rest wait, so there is no background thread to shut down.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{Result, anyhow};

use super::{EngineHit, SearchFilter};
use crate::commit::CommitHash;
use crate::hash::Hash;

const MAX_BATCH: usize = 256;

pub(crate) struct Record {
    pub commit: CommitHash,
    pub mode: String,
    pub query_text: Option<String>,
    pub embedding: Option<Vec<f32>>,
    pub top_k: usize,
    pub filter: SearchFilter,
    pub principal: Option<String>,
    pub hits: Vec<EngineHit>,
}

#[derive(Default)]
struct Queue {
    pending: Vec<(u64, Record)>,
    // anyhow::Error is not Clone; a failed batch fails every record in it.
    done: HashMap<u64, Result<Hash, String>>,
    next: u64,
    leader: bool,
}

type Slot = Arc<(Mutex<Queue>, Condvar)>;

#[derive(Default)]
pub(crate) struct Recorder {
    heads: Mutex<HashMap<String, Slot>>,
}

impl Recorder {
    /// Queue `record` on `head` and block until it is committed.
    /// `commit_batch` commits records in order, one manifest hash per record.
    pub(crate) fn record(
        &self,
        head: &str,
        record: Record,
        commit_batch: impl Fn(&[Record]) -> Result<Vec<Hash>>,
    ) -> Result<Hash> {
        let slot = Arc::clone(
            self.heads
                .lock()
                .expect("recorder poisoned")
                .entry(head.to_string())
                .or_default(),
        );
        let (lock, cv) = &*slot;
        let mut q = lock.lock().expect("record queue poisoned");
        let ticket = q.next;
        q.next += 1;
        q.pending.push((ticket, record));
        loop {
            if let Some(outcome) = q.done.remove(&ticket) {
                return outcome.map_err(|e| anyhow!(e));
            }
            if q.leader {
                q = cv.wait(q).expect("record queue poisoned");
                continue;
            }
            q.leader = true;
            let n = q.pending.len().min(MAX_BATCH);
            let (tickets, records): (Vec<u64>, Vec<Record>) = q.pending.drain(..n).unzip();
            drop(q);
            let outcome = catch_unwind(AssertUnwindSafe(|| commit_batch(&records)));
            q = lock.lock().expect("record queue poisoned");
            let panic = match outcome {
                Ok(Ok(hashes)) => {
                    q.done
                        .extend(tickets.into_iter().zip(hashes.into_iter().map(Ok)));
                    None
                }
                Ok(Err(e)) => {
                    let msg = e.to_string();
                    q.done
                        .extend(tickets.into_iter().map(|t| (t, Err(msg.clone()))));
                    None
                }
                Err(p) => {
                    q.done.extend(
                        tickets
                            .into_iter()
                            .map(|t| (t, Err("record batch panicked".to_string()))),
                    );
                    Some(p)
                }
            };
            // Waiters must never see a leader that is gone.
            q.leader = false;
            cv.notify_all();
            if let Some(p) = panic {
                q.done.remove(&ticket);
                drop(q);
                resume_unwind(p);
            }
        }
    }
}
