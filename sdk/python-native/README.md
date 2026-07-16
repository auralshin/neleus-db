# neleus-native

Native Python binding (PyO3) that **embeds the neleus-db engine in-process**.
No subprocess, no HTTP — the engine runs inside the Python interpreter, so
calls are direct function calls (microseconds), not process spawns.

This is the fast path. The other Python option,
[`sdk/python/neleus.py`](../python), is an HTTP/CLI client for talking to a
remote `serve` instance; use that when the database lives elsewhere. Use this
when you want the database *in* your Python process.

## Build

With maturin (recommended):

```bash
pip install maturin
maturin develop --release        # builds and installs into the current venv
```

Without maturin (uses the bundled script):

```bash
./build.sh                        # writes neleus_native.so next to the script
```

Note: on CPython newer than your PyO3 supports (e.g. 3.14), the script sets
`PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` so the abi3 build goes through.

## Use

```python
import neleus_native as n

db = n.Neleus("./agent_db")        # opens or initializes the directory

manifest, commit = db.put_document("main", "kb.md", "policy text")
hits = db.search("main", "policy", mode="hybrid", top_k=5)

proof = db.prove(commit, hits[0]["chunk"])       # bytes (CBOR bundle)
assert db.verify_proof(proof)["valid"]

# audit, fully in-process
qm = db.record_query("main", "policy", principal="agent:reviewer")
db.commit("main", "audited retrieval", manifests=[qm])
db.checkpoint("main")
db.audit_export("main", "q1.nelaudit")              # offline-verifiable bundle

db.session_append("main", "s1", "hello", role="user", ttl_secs=3600)
```

`search` and `prove` accept a head name or a commit hash as the first
argument — pass a commit hash for time-travel retrieval against history.

## Methods

`Neleus(path)` then: `put_document`, `search`, `prove`, `verify_proof`,
`commit`, `record_query`, `checkpoint`, `audit_export`, `session_append`.

## Test

```bash
./build.sh && python3 test_native.py
```
