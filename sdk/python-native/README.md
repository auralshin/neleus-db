# neleus-native

PyO3 binding that runs the neleus-db engine inside the Python process. For a
remote `serve` instance, use [`sdk/python`](../python).

```bash
pip install maturin && maturin develop --release   # or ./build.sh
```

`build.sh` sets `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` for CPython newer than
PyO3 supports.

```python
import neleus_native as n

db = n.Neleus("./agent_db")  # opens or initializes
manifest, commit = db.put_document("main", "kb.md", "policy text")
hits = db.search("main", "policy", mode="hybrid", top_k=5)
proof = db.prove(commit, hits[0]["chunk"])
assert db.verify_proof(proof)["valid"]
db.checkpoint("main")
db.audit_export("main", "q1.nelaudit")
db.session_append("main", "s1", "hello", role="user", ttl_secs=3600)
```

Methods:

- `put_document(head, source, text, chunk_size=512, overlap=None, author="agent")`
- `search(head, query=None, embedding=None, mode="hybrid", top_k=10, commit=None, principal=None)`
- `prove(commit, chunk, include_content=True)`, `verify_proof(proof_cbor)`
- `commit(head, message, manifests=None, author="agent")`
- `record_query(head, query, top_k=10, principal=None)`
- `checkpoint(head)`, `audit_export(head, out)`
- `session_append(head, session_id, content, role=None, ttl_secs=None)`

`search` is recorded on `head`; `commit` searches a past commit.

Test: `./build.sh && python3 test_native.py`.
