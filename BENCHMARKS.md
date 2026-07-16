# Benchmarks

Two kinds of numbers, kept strictly apart:

1. **Measured** — same machine, same corpus, same harness (`cargo bench
   --bench compare_sql`). Apple M3 Pro, 18 GB, macOS, APFS. Reproducible.
2. **Published claims** — vendor/third-party numbers for systems that cannot
   be fairly benchmarked in-process (SaaS memory APIs, server databases).
   Cited, dated, and explicitly NOT comparable to row 1 latencies: they
   measure different operations on different hardware.

## 1. Measured: neleus-db vs SQLite (same machine, same corpus)

Corpus: 10,000 text chunks (BM25), 5,000 of them with 128-dim embeddings,
10,000 KV pairs. SQLite runs file-backed with WAL + `synchronous=NORMAL` +
FTS5 — its best practical configuration for this shape. neleus-db runs the
default `durability: os` policy, which is the same durability class
(crash-of-process safe; power loss can drop the most recent writes in both).

| Operation | neleus-db | SQLite | Ratio |
|---|---|---|---|
| Point get (warm) | **0.48 µs** | 2.17 µs | **4.5x faster** |
| BM25 top-10 over 10k chunks | **115 µs** | 572 µs (FTS5) | **5.0x faster** |
| Vector top-10 (HNSW, 5k × 128d) | **232 µs** | n/a — no native ANN in SQLite | — |
| Hybrid top-10 (BM25 ∥ vector, RRF) | **408 µs** | n/a | — |
| Point set, coalesced (8 concurrent writers) | **234 µs/op** | ~29 µs | ~8x slower |
| Point set, direct single op | 398 µs | **29 µs** | ~13.7x slower |

The state store is a prolly tree (content-defined B+-tree, DESIGN §5). With
fanout ~32 the tree is shallow (~3 node loads at 10k keys), so warm point-get
measures **0.48 µs** — faster than the former segment store's 0.68 µs, not a
regression. Single-op set is 398 µs (was 754 µs on the segment store);
coalesced writes are 234 µs/op (tight CI, load-insensitive). BM25/vector/hybrid
are unaffected by the state rewrite.

Scale points and ingest component breakdown (`cargo bench --bench scale`):

| Component | Result |
|---|---|
| BLAKE3 hash-only, 100k chunks, 1 thread | 12.5 ms |
| Bulk document ingest, 100k chunks (hash + encrypt + pack-first write + Merkle commit) | **0.22 s** |
| Per-chunk-manifest ingest, 10k chunks with 1536d embeddings (3 loose objects per chunk) | 15.1 s (~0.5 ms/chunk) |
| BM25 index build, 100k chunks | 1.4 s |
| HNSW build, 10k × 1536d (SQ8 metric, batched-parallel) | 4.8 s |
| BM25 top-10 over **100k** chunks | 1.13 ms |
| Vector top-10, **10k × 1536d** (SQ8 traversal, f32 rerank) | 1.48 ms |

These are separate measurements: the 0.22 s row is the 100k *text* corpus
pipeline (no vectors); the 4.8 s row is graph construction for a 10k
*vector* corpus. They are not one pipeline.

Write path: the state store is a prolly tree (content-defined B+-tree,
DESIGN §5). A `set` copy-on-writes its short root→leaf path — `~log32(n)` nodes
— as content-addressed objects, each ~8 filesystem metadata operations
(temp-create + hard-link + unlink, rename-atomic ref update) at APFS's
~60–100 µs each; SQLite pays one sequential WAL append. Bulk loads (`set_many`
/ `write_many` into an empty base) build the canonical tree bottom-up in one
pass, writing each node once instead of re-walking the path per key. The
coalescer batches concurrent single writes into one flush: **~234 µs/op** under
8 writers, unchanged from the former segment store.

Notes:

- **BM25 beats SQL.** BM25 search is 5.0x faster than FTS5 on the same data
  (dense score accumulation + MaxScore term pruning). Every neleus read also
  carries provenance (commit + chunk hash) that SQLite rows do not have. Warm
  point-get is a shallow B+-tree descent (~3 node loads at 10k keys) measured
  at 0.48 µs — faster than the segment store, recovering the read speed the
  binary treap had regressed.
- **BM25 scaling caveat:** 10k -> 100k chunks scaled latency ~10x on this
  synthetic corpus because its 34-word vocabulary makes every query term
  maximally dense — MaxScore's worst case. Real (Zipfian) corpora have
  high-IDF rare terms where pruning skips most postings; treat 1.13 ms as
  the dense-corpus upper bound at 100k.
- **Two ingestion shapes.** Bulk documents take the pack-first path: chunks
  are hashed/encrypted in parallel and appended to one pack file + index
  (two sequential files instead of 100k loose creates) — 0.22 s per 100k.
  Per-chunk `ChunkManifest` ingestion (one text blob, one embedding blob,
  one manifest object per chunk) still writes loose objects individually;
  batch it with `BlobStore::put_many` where the call site allows.
- **Hybrid runs both modalities concurrently** (scoped threads over
  immutable segments): ~max(bm25, vector) + fusion.
- **1536d is the realistic embedding size** (OpenAI text-embedding-3-small).
  HNSW construction and traversal both run on SQ8 int8 codes there, with
  f32 reranking of the oversampled candidate set; recall@10 >= 0.90 vs the
  exact oracle is enforced in tests for both metrics. SQ8 engages only at
  >= 256 dims.
- Vector + hybrid have no SQLite row because stock SQLite (and stock
  Postgres) has no ANN index.

### SQLCipher

SQLCipher is SQLite + page-level AES (AES-256-CBC + HMAC-SHA512, Argon2id
KDF in v4). Official guidance: **5–15%** overhead; community benchmarks show
~5–6% on batched inserts, ~3.4% on indexed reads, but **~5x slower
(≈496%)** on unindexed full-table scans, because every page must be
decrypted before the WHERE clause can be evaluated. With AES-NI and proper
indexes, 2–5% is achievable. Apply those to the SQLite column for an
encrypted-SQL baseline.

neleus-db's model differs structurally: encryption is per content-addressed
object, the master key is Argon2id-derived once at open, and the read cache
holds plaintext in-process — so warm reads (the 0.67 µs path) pay zero
decryption regardless of scan shape. There is no unindexed-scan cliff
because retrieval always goes through the index segments.

### Postgres / pgvector

A fair in-process comparison is impossible (server database, network hop,
buffer pool). Published reference points at the 100k–1M vector scale:

- pgvector + pgvectorscale (Timescale benchmark, 50M Cohere 768d vectors):
  471 QPS at 99% recall vs Qdrant 41 QPS; p95 28x lower than Pinecone
  storage-optimized. Vanilla pgvector degrades from ~1,200 to ~280 QPS
  between 1M and 100M vectors (single-node limits).
- Typical production HNSW p99 at 1M vectors / 95–99% recall: 10–50 ms
  depending on hardware and ef_search.
- These are all **server-side numbers before network** (add 0.1–5 ms per
  hop in production). The measured neleus path is in-process: 239 µs at
  128d, 1.69 ms at 1536d, zero hops. For agent loops where retrieval sits
  on the critical path of every LLM call, in-process beats client-server
  by the network round-trip alone, every call.

What Postgres buys that neleus does not have: SQL, joins, mature replication
topologies, decades of operational tooling. What neleus has that Postgres
does not: content-addressed tamper-evidence, offline proofs, time-travel
retrieval as a query parameter, and an embedded zero-infra mode.

## 2. Published claims: agent-memory products (June 2026)

These systems measure **end-to-end memory pipeline quality/latency** (LLM
calls included in some numbers), not storage-engine operations. They are
listed for positioning, not as same-harness comparisons.

| Product | Benchmark claims | Latency claims | Source |
|---|---|---|---|
| Mem0 (original) | LOCOMO ~66% ±0.16; +26% rel. vs OpenAI Memory; ~1.8K tokens/conv (90% reduction) | p95 "91% lower" than OpenAI (absolute undisclosed) | arXiv 2504.19413, ECAI 2025 |
| Mem0 (2026 algorithm) | LoCoMo **92.5**; LongMemEval **94.4**; BEAM 64.1 @1M / 48.6 @10M tokens; ~7K tokens/retrieval | — | vendor, April 2026 |
| Zep | LOCOMO 75.14% ±0.17 self-reported (84% retracted; Mem0's correction: 58.44%); latest claim 80% @ <200 ms; DMR 94.8%; LongMemEval +15–18.5% vs full-context, 1.6K vs 115K tokens | <200 ms (Dec 2025 claim); p50 1.292 s in Mem0's sequential eval | Zep blog, arXiv 2501.13956, getzep/zep-papers#5 |
| Zep vs Mem0 (independent) | Atlan, April 2026: Zep 63.8% vs Mem0 49.0% on LongMemEval (GPT-4o) | — | Atlan |
| Supermemory | LongMemEval-S 85.4% self-reported; LoCoMo P@1 59.7%, R@10 83.5%; 99.4% context reduction | "<300 ms recall" self-reported; its 4 s/7–8 s claims for Zep/Mem0 contradict Mem0's own tables | vendor; no third-party verification |
| Letta (MemGPT) | DMR 93.4%; LoCoMo 74.0% using **plain filesystem storage** — their point: these benchmarks are harness-dominated | LangMem comparison point: p50 17.99 s, p95 59.82 s ("impractical") | letta.com |

Read the LOCOMO column with suspicion: the same system scored 84%, 75.14%,
58.44%, and 80% depending on who configured the harness, which categories
were counted (Category 5 lacks ground truth), single vs 10-run averaging,
and sequential vs parallel ingestion. Both vendors concede the dataset has
quality problems. LongMemEval is the most discriminating public benchmark
(Atlan's independent run: Zep 63.8 / Mem0 49.0 — far below both vendors'
self-reported numbers); DMR is saturated (Zep's own full-context baseline
hits 94.4%). Latency claims measure different operations (end-to-end answer
vs search-only vs recall-only) and are not mutually comparable.

neleus-db is a storage/retrieval engine, not a memory pipeline: it does not
call an LLM, so LOCOMO/LongMemEval scores do not apply directly. Its raw
retrieval latencies (hundreds of microseconds hybrid, in-process) sit 3–4
orders of magnitude below the sub-second pipeline latencies above — the
storage layer is not the bottleneck of any of those pipelines. A LongMemEval
harness over neleus retrieval is the right next experiment to publish.

## 3. The verifiability gap

Documented capability check across the agent-memory market (June 2026 — from
docs/marketing absence, not source audits):

| Product | Cryptographic tamper-evidence / provenance proofs |
|---|---|
| Mem0 | No (metadata-level scope provenance only) |
| Zep | No (bi-temporal lineage, not tamper-evidence) |
| Supermemory | No |
| Letta | No (memory blocks explicitly editable) |
| Cognee | No (pipeline lineage only) |
| SQLite/SQLCipher | No (encryption ≠ tamper-evidence) |
| Postgres | No |
| **neleus-db** | **Yes**: content-addressed objects, Merkle state proofs, signed commits, checkpoint chains, offline-verifiable chunk proofs, content-addressed query audit log |

The research literature names this gap explicitly. "Portable Agent Memory"
(arXiv 2605.11032, May 2026) surveys the five production systems above,
finds none offer cryptographic verifiability, and proposes — as a research
prototype — a **Merkle-DAG provenance structure with BLAKE3
content-addressing and Ed25519 root signing**: the architecture neleus-db
ships today. SuperLocalMemory (arXiv 2603.02240) adds per-memory provenance
tracking against memory poisoning, also research-only. Zep's SOC 2 (access
auditing) and Cognee's air-gap option (isolation) are the closest shipping
features; neither is verification. No shipping product combines fast hybrid
retrieval with cryptographic verifiability. That combination is this
engine's position.

## 4. Measured: proof size and verification time

Same machine and harness as §1 (`cargo bench --bench state`). Each row is a
single measured point at the stated size, not a curve; the notes give the
asymptotic shape each one moves along.

| Artifact | Size | Generate | Verify (offline) |
|---|---|---|---|
| State inclusion proof (100 keys) | 2.4 KB | 3.4 µs | **7.7 µs** |
| State non-inclusion proof (100 keys) | 1.2 KB | 1.5 µs | **4.3 µs** |
| Chunk proof (depth-9 ancestry, content included) | 11.6 KB | 471 µs | **32 µs** |
| Audit bundle (64 retrievals, unsigned) | 108 KB | 7.03 ms (export) | **0.95 ms** |

- **State proofs** are a single root→leaf path in the prolly tree (a
  content-defined B+-tree) — both membership and non-membership are
  **O(log_B n) in the key count, independent of the number of writes**
  (DESIGN.md §5–6). This is the fix for the former segment-scan non-membership
  cost, which grew with the live segment count. With fanout ~32 the tree is
  shallow: a 1000-key state proves in a ≤6-node path (test
  `proofs_membership_and_non_membership`), and millions of keys stay ~3–4
  nodes. Nodes are wider than a binary tree's — each carries more bytes — but
  the path is far shorter, so proofs stay small and shrink relative to a binary
  structure as n grows.
- **Chunk proofs** carry the commit ancestry they span plus, optionally, the
  chunk bytes — here content is included, which dominates the 11.6 KB; size
  grows with ancestry depth and content length.
- **Audit bundles** (`NELAUDIT`) carry one record per retrieval plus the
  referenced commit/manifest bytes, so size grows with the retrieval count in
  the window. These numbers are for the unsigned bundle; signing adds one
  ed25519 verification over the footer.
- **Verification is offline** — no database, no network: a state proof is
  checked against the root hash alone by recomputing each node's hash and the
  BST path; chunk/audit claims re-derive from carried bytes by BLAKE3 hash
  equations and a CBOR decode. Verify time tracks proof size.

Still uninstrumented: size/verify *curves* across proof depth, state size,
and bundle length (only the points above are measured), and signed-bundle
verification.

## Reproducing

```bash
cargo bench --bench compare_sql       # measured table, your machine
cargo test                            # correctness suite (incl. HNSW recall >= 0.90 oracle test)
```

The bench prints ingest/index build times to stderr and writes criterion
reports under `target/criterion/`.
