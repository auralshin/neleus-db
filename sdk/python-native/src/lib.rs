//! Native Python binding: embeds the neleus-db `Engine` in-process. No
//! subprocess, no HTTP — the engine runs inside the Python interpreter, so
//! calls are direct function calls (microseconds), not process spawns.
//!
//! ```python
//! import neleus_native as n
//! db = n.Neleus("./agent_db")
//! manifest, commit = db.put_document("main", "kb.md", "policy text")
//! hits = db.search("main", "policy", mode="hybrid", top_k=5)
//! proof = db.prove(commit, hits[0]["chunk"])
//! assert db.verify_proof(proof)["valid"]
//! ```

use std::path::PathBuf;
use std::sync::Mutex;

use neleus_db::engine::SearchFilter;
use neleus_db::{Engine, Hash};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn parse_hash(s: &str) -> PyResult<Hash> {
    s.parse::<Hash>()
        .map_err(|e| PyValueError::new_err(format!("invalid hash {s:?}: {e}")))
}

/// In-process neleus-db engine.
#[pyclass]
struct Neleus {
    // Engine is shared behind a Mutex so the pyclass is Send; the engine's
    // own reads are already concurrent, this just satisfies pyclass bounds.
    engine: Mutex<Engine>,
}

#[pymethods]
impl Neleus {
    /// Open (or initialize) a database directory.
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let p = PathBuf::from(path);
        if !p.join("meta").join("config.json").exists() {
            neleus_db::Database::init(&p).map_err(err)?;
        }
        let engine = Engine::open(&p).map_err(err)?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Chunk a document, store it, commit it, and index it.
    /// Returns `(manifest_hash, commit_hash)`.
    #[pyo3(signature = (head, source, text, chunk_size=512, overlap=64, author="agent"))]
    fn put_document(
        &self,
        head: &str,
        source: &str,
        text: &str,
        chunk_size: usize,
        overlap: usize,
        author: &str,
    ) -> PyResult<(String, String)> {
        let engine = self.engine.lock().map_err(err)?;
        let (manifest, commit) = engine
            .put_document(
                head,
                source,
                text.as_bytes(),
                neleus_db::manifest::ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size,
                    overlap,
                },
                None,
                author,
            )
            .map_err(err)?;
        Ok((manifest.to_string(), commit.to_string()))
    }

    /// Search. `at` is a head name or a commit hash (time-travel). `mode` is
    /// "semantic", "vector", or "hybrid". Returns a list of
    /// `{chunk, score, preview}` dicts.
    #[pyo3(signature = (at, query=None, embedding=None, mode="hybrid", top_k=10))]
    fn search<'py>(
        &self,
        py: Python<'py>,
        at: &str,
        query: Option<&str>,
        embedding: Option<Vec<f32>>,
        mode: &str,
        top_k: usize,
    ) -> PyResult<Bound<'py, PyList>> {
        let engine = self.engine.lock().map_err(err)?;
        let commit = engine.resolve_commit(at).map_err(err)?;
        let filter = SearchFilter::default();
        let hits = match mode {
            "semantic" => engine
                .search_semantic(commit, query.unwrap_or(""), top_k, &filter)
                .map_err(err)?,
            "vector" => {
                let e = embedding
                    .ok_or_else(|| PyValueError::new_err("vector mode requires embedding"))?;
                engine.search_vector(commit, &e, top_k, &filter).map_err(err)?
            }
            "hybrid" => engine
                .search_hybrid(commit, query, embedding.as_deref(), top_k, &filter)
                .map_err(err)?,
            other => return Err(PyValueError::new_err(format!("unknown mode {other:?}"))),
        };

        let out = PyList::empty_bound(py);
        for h in hits {
            let d = PyDict::new_bound(py);
            d.set_item("chunk", h.chunk_hash.to_string())?;
            d.set_item("score", h.score)?;
            d.set_item("preview", h.text_preview)?;
            d.set_item("commit", h.commit.to_string())?;
            out.append(d)?;
        }
        Ok(out)
    }

    /// Fetch a blob (e.g. a chunk's full text) by hash. Search returns a
    /// truncated `preview`; use this to get the bytes the agent actually saw.
    fn get_blob<'py>(&self, py: Python<'py>, hash: &str) -> PyResult<Bound<'py, PyBytes>> {
        let engine = self.engine.lock().map_err(err)?;
        let bytes = engine.db().blob_store.get(parse_hash(hash)?).map_err(err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Build an offline-verifiable chunk proof. Returns the CBOR bundle bytes.
    #[pyo3(signature = (commit, chunk, include_content=true))]
    fn prove<'py>(
        &self,
        py: Python<'py>,
        commit: &str,
        chunk: &str,
        include_content: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let engine = self.engine.lock().map_err(err)?;
        let proof = engine
            .prove(parse_hash(commit)?, parse_hash(chunk)?, include_content)
            .map_err(err)?;
        let bytes = neleus_db::canonical::to_cbor(&proof).map_err(err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Verify a chunk-proof bundle. Returns `{valid, anchor?}`.
    fn verify_proof<'py>(&self, py: Python<'py>, proof_cbor: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        let proof: neleus_db::ChunkProof = match neleus_db::canonical::from_cbor(proof_cbor) {
            Ok(p) => p,
            Err(e) => {
                d.set_item("valid", false)?;
                d.set_item("error", e.to_string())?;
                return Ok(d);
            }
        };
        match neleus_db::verify_chunk_proof(&proof) {
            Ok(anchor) => {
                d.set_item("valid", true)?;
                d.set_item("anchor", anchor)?;
            }
            Err(e) => {
                d.set_item("valid", false)?;
                d.set_item("error", e.to_string())?;
            }
        }
        Ok(d)
    }

    /// Commit on a head, optionally recording an audit manifest hash list.
    #[pyo3(signature = (head, message, manifests=None, author="agent"))]
    fn commit(
        &self,
        head: &str,
        message: &str,
        manifests: Option<Vec<String>>,
        author: &str,
    ) -> PyResult<String> {
        let engine = self.engine.lock().map_err(err)?;
        let hashes = manifests
            .unwrap_or_default()
            .iter()
            .map(|s| parse_hash(s))
            .collect::<PyResult<Vec<_>>>()?;
        let commit = engine.commit(head, author, message, hashes).map_err(err)?;
        Ok(commit.to_string())
    }

    /// Record a retrieval as a content-addressed audit manifest. Returns its
    /// hash; attach it with `commit(...)` to make it durable.
    #[pyo3(signature = (at, query, top_k=10, principal=None))]
    fn record_query(
        &self,
        at: &str,
        query: &str,
        top_k: usize,
        principal: Option<&str>,
    ) -> PyResult<String> {
        let engine = self.engine.lock().map_err(err)?;
        let commit = engine.resolve_commit(at).map_err(err)?;
        let filter = SearchFilter::default();
        let hits = engine
            .search_semantic(commit, query, top_k, &filter)
            .map_err(err)?;
        let qm = engine
            .record_query(commit, "semantic", Some(query), None, top_k, &filter, principal, &hits)
            .map_err(err)?;
        Ok(qm.to_string())
    }

    /// Append a checkpoint to the head's transparency-log chain.
    fn checkpoint(&self, head: &str) -> PyResult<String> {
        let engine = self.engine.lock().map_err(err)?;
        let h = engine.checkpoints().create(head, None).map_err(err)?;
        Ok(h.to_string())
    }

    /// Export a self-contained, offline-verifiable audit bundle to `out`.
    fn audit_export(&self, head: &str, out: &str) -> PyResult<usize> {
        let engine = self.engine.lock().map_err(err)?;
        let summary =
            neleus_db::audit::export(engine.db(), head, 0, u64::MAX, &PathBuf::from(out), None)
                .map_err(err)?;
        Ok(summary.retrievals)
    }

    /// Append a session turn with optional TTL.
    #[pyo3(signature = (head, session_id, content, role=None, ttl_secs=None))]
    fn session_append(
        &self,
        head: &str,
        session_id: &str,
        content: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> PyResult<u64> {
        let engine = self.engine.lock().map_err(err)?;
        let (seq, _) = engine
            .sessions()
            .append(head, session_id, role, content.as_bytes(), ttl_secs)
            .map_err(err)?;
        Ok(seq)
    }
}

#[pymodule]
fn neleus_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Neleus>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
