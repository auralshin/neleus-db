# Examples

Run with `cargo run --example <name>`.

| Example | Shows |
|---|---|
| `01_basic_blob_storage` | Blob put/get and deduplication by hash |
| `02_state_and_commits` | Versioned state, commits, and reads at past roots |
| `03_document_chunking` | Fixed-size chunking into a `DocManifest` |
| `05_state_proofs` | Membership, non-membership, and deletion proofs |
| `07_retrieval_quality` | nDCG@10 and Recall@10 on a BEIR corpus; takes two JSONL files (see file header) |
| `sync_count` | Helper for `benches/tools/sync-count.sh` |
| `06_claude_run.py` | Python: audit a Claude call end to end (needs `anthropic` and an API key; see file header) |
