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
| Point get (warm) | **0.48 µs** | 3.19 µs | **6.7x faster** |
| BM25 top-10 over 10k chunks | **164 µs** | 866 µs (FTS5) | **5.3x faster** |
| Vector top-10 (HNSW, 5k × 128d) | **293 µs** | n/a — no native ANN in SQLite | — |
| Hybrid top-10 (BM25 ∥ vector, RRF) | **482 µs** | n/a | — |
| Point set, coalesced (8 concurrent writers) | **199 µs/op** | 35.8 µs | ~5.6x slower |
| Point set, direct single op | 430 µs | **35.8 µs** | ~12.0x slower |

The state store is a prolly tree (content-defined B+-tree, DESIGN §5). With
fanout ~32 the tree is shallow (~3 node loads at 10k keys), so warm point-get
measures **0.48 µs**. Single-op set is 430 µs; the coalescer amortizes 8
concurrent writers to 199 µs/op.

Each row is the mean of three independent runs. The engine's own figures vary
by ≤1.3% run-to-run; SQLite is noisier (FTS5 3.7%, insert 4.1%), and its FTS5
median moved 11% across our three runs, which alone shifts the BM25 ratio from
4.8x to 5.3x. Do not read these ratios to better than half a significant figure.

Scale points and ingest component breakdown (`cargo bench --bench scale`):

| Component | Result |
|---|---|
| BLAKE3 hash-only, 101k chunks, 1 thread | 17.8 ms |
| Bulk document ingest, 100k chunks (chunk + hash + pack-first write + Merkle commit) | **0.41 s** (~4.1 µs/chunk) |
| Per-chunk-manifest ingest, 10k chunks with 1536d embeddings (3 loose objects per chunk) | 19.7 s (~2.0 ms/chunk) |
| BM25 index build, 100k chunks | 1.64 s |
| HNSW build, 10k × 1536d (SQ8 metric, batched-parallel) | 3.16 s |
| BM25 top-10 over **100k** chunks | 1.65 ms |
| Vector top-10, **10k × 1536d** (SQ8 traversal, f32 rerank) | 459 µs |

These are separate measurements: the 0.41 s row is the 100k *text* corpus
pipeline (no vectors); the 3.16 s row is graph construction for a 10k
*vector* corpus. They are not one pipeline. Encryption is **off** in all of
the above, so these figures isolate content-addressing cost, not AEAD cost.

The bulk path is ~480x cheaper per chunk than the per-chunk-manifest path
(4.1 µs vs 2.0 ms). That gap is per-file metadata operations, not hashing:
BLAKE3 over the whole corpus is 17.8 ms, about 176 ns/chunk.

Write path: the state store is a prolly tree (content-defined B+-tree,
DESIGN §5). A `set` copy-on-writes its short root→leaf path — `~log32(n)` nodes
— as content-addressed objects, each ~8 filesystem metadata operations
(temp-create + hard-link + unlink, rename-atomic ref update) at APFS's
~60–100 µs each; SQLite pays one sequential WAL append. Bulk loads (`set_many`
/ `write_many` into an empty base) build the canonical tree bottom-up in one
pass, writing each node once instead of re-walking the path per key. The
coalescer batches concurrent single writes into one flush: **~199 µs/op** under
8 writers, a 2.2x amortization of the 430 µs single-op path.

Notes:

- **BM25 beats SQL.** BM25 search is 5.3x faster than FTS5 on the same data
  (dense score accumulation + MaxScore term pruning). Every neleus read also
  carries provenance (commit + chunk hash) that SQLite rows do not have. Warm
  point-get is a shallow B+-tree descent (~3 node loads at 10k keys) measured
  at 0.48 µs.
- **BM25 scaling caveat:** 10k -> 100k chunks scaled latency ~10x on this
  synthetic corpus because its 34-word vocabulary makes every query term
  maximally dense — MaxScore's worst case. Real (Zipfian) corpora have
  high-IDF rare terms where pruning skips most postings; treat 1.65 ms as
  the dense-corpus upper bound at 100k.
- **Two ingestion shapes.** Bulk documents take the pack-first path: chunks
  are hashed in parallel and appended to one pack file + index
  (two sequential files instead of 100k loose creates) — 0.41 s per 100k.
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
holds plaintext in-process — so warm reads (the 0.48 µs path) pay zero
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
  hop in production). The measured neleus path is in-process: 293 µs at
  128d, 459 µs at 1536d, zero hops. For agent loops where retrieval sits
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
| State inclusion proof (100 keys) | 2.4 KB | 3.35 µs | **7.48 µs** |
| State non-inclusion proof (100 keys) | 1.2 KB | 1.45 µs | **4.40 µs** |
| Chunk proof (depth-9 ancestry, content included) | 11.6 KB | 532 µs | **32.4 µs** |
| Audit bundle (64 retrievals, unsigned) | 194 KB | 7.92 ms (export) | **1.32 ms** |

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

Still uninstrumented: size/verify curves across proof depth and state size,
and signed-bundle verification. Chain-length and bundle-length curves are in
§5.

## 5. Measured: auditor-side cost and the tenant-statistics channel

`cargo bench --bench verifiability`. Same machine as §1.

**Checkpoint chains are linear.** ~43 µs per checkpoint to verify, tip to
genesis:

| Chain length J | 1 | 10 | 100 | 1,000 | 10,000 |
|---|---|---|---|---|---|
| `verify_chain` | 64 µs | 361 µs | 3.48 ms | 55.4 ms | **434 ms** |

Projected by anchoring cadence: one/day → J≈365/yr → 16 ms. One/hour →
J≈8.8k/yr → 380 ms. One/minute → J≈526k/yr → ~23 s. **Checkpoint cadence is a
security-relevant setting**: anchoring more finely shrinks the
post-compromise window but costs verification time linearly. A Merkle history
tree would answer the same query in ~14 hashes at J=10⁴.

**Audit bundles grow linearly at ~3.1 KB / 20 µs per retrieval.**

| Retrievals R | 1 | 8 | 64 | 512 |
|---|---|---|---|---|
| Bundle bytes | 3,991 | 25,726 | 199,704 | 1,592,312 |
| Per retrieval | — | 3,216 B | 3,120 B | **3,110 B** |
| In-process verify | 47.9 µs | 187 µs | 1.41 ms | 10.5 ms |
| Cold standalone (`neleus-verify` process) | 31.6 ms* | 2.61 ms | 4.37 ms | 13.6 ms |

\*first run, binary not yet in page cache. Steady-state process overhead is
2.4–3.2 ms, which dominates small bundles. Extrapolated: 1M retrievals ≈
3.1 GB and ≈20 s to verify.

**Cold vs warm state proofs.** A state proof verifies in **13.5 µs warm** but
**109 ms** against a freshly opened database — almost all of it
`Database::open` (recovery lock, WAL replay, orphan-temp sweep), not
verification. Use `StateProof::verify`, which rebuilds and re-hashes the
manifest from the proof's own bytes and needs no store at all.

### Fixed: BM25 collection statistics are now tenant-scoped

BM25 computes `idf` from `N` (chunk count) and `df` (document frequency).
These were segment-global and computed **before** metadata filters, so a
tenant's own score was a function of documents it could not see. Two queries
recovered another tenant's corpus size and any term's document frequency
*exactly*: probe a nonce term (df=1) to solve for `N`, then probe the target
term to solve for its `df`. Inverting a measured score at (N, df) = (1001, 37)
recovered df = 37.000000.

Collection statistics are now scoped to the visible partition, and a term
occurring only in hidden documents is indistinguishable from an absent one.
Measured after the fix: the attacker's own score is bit-identical across 0,
1, 2, 10, 100 and 500 hidden documents, whether or not those documents
contain the probe term. Guarded by `tenant_scores_are_independent_of_hidden_documents`
and by the `[q5]` assertion in `cargo bench --bench verifiability`.

### Fixed: selective filters no longer degenerate HNSW into a full scan

The beam admits a node when it beats the worst *matching* result, so under a
selective filter that radius is set by the ef-th nearest **visible** vector and
admits most of the segment; the early exit cannot fire until ef matching
results exist. Traversal touched 79-89% of all vectors, at a cost proportional
to rows the caller cannot see -- and was **slower than not using the index**.

The graph/scan decision is now selectivity-aware (graph only when the filter
leaves >= half the segment visible). Measured at 1200 visible vectors, dim 64:

| hidden vectors | 0 | 1,000 | 5,000 | 20,000 |
|---|---|---|---|---|
| before | 26.8 µs | 44.1 µs | 121 µs | **524 µs** |
| after | 27.1 µs | 44.9 µs | 93.8 µs | **265 µs** |

2x faster at 20k hidden, leak amplitude 19.6x -> 9.8x, zero recall cost (the
exact path is the oracle the recall tests pin against).

### Fixed (vector): segments carry a tenant index

A tenant-scoped filter now starts from its own partition instead of scanning
every chunk, and allowed docs map to vector nodes by binary search. Measured
with a tenant holding **100 documents** as co-tenant volume grows:

| co-tenant docs | 0 | 1,000 | 10,000 | 50,000 |
|---|---|---|---|---|
| vector before | 4.7 µs | 10.1 µs | 54.9 µs | **272 µs** |
| vector after | 10.9 µs | 6.1 µs | 5.9 µs | **5.6 µs** |
| bm25 before | 5.0 µs | 9.9 µs | 66.6 µs | **320 µs** |
| bm25 after | 4.9 µs | 4.7 µs | 24.7 µs | **104 µs** |

Vector is **flat**: 49x faster at 50k co-tenant docs, and no signal left.
This is a performance fix as much as a leak fix -- a small tenant in a large
database was paying 65x for data it cannot see.

**Residual (lexical):** BM25 walks posting lists, and postings are shared
across tenants, so a common term's list is as long as the segment regardless
of who asks. The dense score accumulator and allowed-doc mask are also O(total).
Closing it needs per-tenant *postings*, i.e. separate segments per tenant.
Until then: **do not put mutually distrusting tenants in one segment.**

### Fixed: retrieval records are sequence-chained

Records now carry `seq` (contiguous per head) and `prev`. `verify_bundle`
checks both, so removing a record from an exported bundle is caught even
though every surviving record still hashes correctly and is still reachable
from the tip. Covered by `withheld_retrieval_is_detected`. This detects
post-hoc removal, **not** a retrieval that was never recorded: recording is
still caller-requested, so the counter simply never advances.

### Fixed: audit records were never committed

`search --audit` recorded a `QueryManifest` but did not attach it to the head.
`audit::collect` walks commits, so `audit export` returned **0 retrievals**,
and `db gc --prune` reclaimed the record as unreachable garbage. The
documented audit workflow produced empty bundles. `record_query_at_head` now
commits the record; `tests/audit_flow.rs` covers export, offline verification,
and survival of a prune.

### Fixed: gc destroyed the transparency log

The mark phase walked `refs/heads` and `refs/states` only. Checkpoints are
referenced by no commit — that independence is what makes the chain survive a
history rewrite — so `db gc --prune` swept the entire chain and
`verify_chain` failed on a missing object. Checkpoint refs are now a mark
root, and the commits they pin are kept alive with them. The same pass added
`QueryManifest` and `SummaryManifest` to the fail-closed manifest classifier,
which would otherwise abort every prune once either became reachable.

### Fixed: Merkle roots now determine their own leaf count

The tree paired leaves left-to-right and duplicated a lone trailing node, so
`root([a,b,c]) == root([a,b,c,c])`: a root did not fix its leaf count and a
proof could be replayed against a log the prover never had. (Reachable only
from test-only helpers, so nothing on disk was affected.)

Rebuilt in the RFC 6962 shape (split at the largest power of two below `n`),
with the leaf count sealed into the published root. This adds **consistency
proofs**, which a linear hash chain cannot express at any cost: given an old
anchor and a new root, a verifier confirms the log only ever grew.

| log size | inclusion | bytes | consistency | bytes |
|---|---|---|---|---|
| 10³ | 10 hashes | 694 | 9 hashes | 628 |
| 10⁴ | 14 hashes | 958 | 12 hashes | 826 |
| 10⁵ | 17 hashes | 1158 | 14 hashes | 960 |

For reference, immudb's inclusion proof is a flat 622 B. About half our excess
is that `Hash` serializes as a 64-char hex string rather than 32 raw bytes.

**Now wired into checkpoints.** Each checkpoint publishes `log_root`, a Merkle
root over every commit checkpointed on its head. Anchor verification stops
being a chain walk:

| J | chain walk (old) | inclusion proof | verify | consistency |
|---|---|---|---|---|
| 100 | 2.42 ms | 7 hashes, 494 B | 1.07 µs | 1.18 µs |
| 1,000 | 29.2 ms | 10 hashes, 694 B | 1.50 µs | 1.80 µs |
| 5,000 | 138 ms | 13 hashes, 892 B | **1.84 µs** | 2.06 µs |

~75,000x faster at J=5000, and offline: proofs need no database. Consistency
proofs are new capability, not just a speedup -- a verifier holding last
quarter's digest can confirm history was appended to, not rewritten.

Appending is incremental, not a rebuild: each checkpoint carries the perfect
subtree roots its log decomposes into (width = popcount of the length), so a
new entry is a binary increment over O(log J) hashes. Measured flat:

| chain length J | 100 | 1,000 | 5,000 | 10,000 |
|---|---|---|---|---|
| cost per `checkpoint new` | 1.46 ms | 1.30 ms | 1.30 ms | 1.24 ms |

A rebuild would have walked the chain instead: ~400 ms of object reads at
J=10,000. Proof *generation* still gathers all leaves, which is inherent.

## 6. Adversarial evaluation

`cargo test --test adversarial -- --nocapture`. Twelve attacks by an operator
that controls storage and serving code. Outcomes are asserted, **including the
one that succeeds**, so a gap that later closes fails the suite rather than
passing quietly.

| attack | detected | by |
|---|---|---|
| Forge a commit into an anchored log | yes | log root |
| Replay a proof at another index | yes | sealed index |
| Rewrite history below an anchor | yes | consistency proof |
| Truncate the log | yes | root mismatch |
| Equivocate between verifiers | yes | anchor comparison |
| Withhold a record from a bundle | yes | sequence gap |
| Swap content into a chunk proof | yes | blob hash |
| Truncate a chunk proof's ancestry | yes | parent link |
| Replay a state proof at another root | yes | sealed root |
| Claim a present key is absent | yes | leaf inspection |
| Reattach erased content | yes | erasure flag |
| **Serve retrievals, record none** | **NO** | *an empty log is a valid log* |

Three of the history attacks were undetectable before the Merkle log landed:
a linear chain cannot express consistency between two log sizes.

The undetected one is structural. Sequence numbers make *removal* detectable;
they cannot make *absence* detectable. Closing it needs the record to be
created by something the operator does not control.

Limits: the attacks are fixed in advance, not chosen adaptively in response to
what verification rejected, and they exercise the library rather than a
deployment.

## Reproducing

```bash
cargo bench --bench compare_sql       # measured table, your machine
cargo bench --bench scale             # 100k chunks, 1536d vectors, coalesced writes
cargo bench --bench state             # proof size + offline verification time
cargo bench --bench verifiability     # chain scaling, cold audit, tenant leakage
cargo test                            # 311 tests (incl. HNSW recall >= 0.90 oracle)
```

The benches print component timings to stderr and write criterion reports
under `target/criterion/`.
