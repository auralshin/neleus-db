# Benchmarks

Two kinds of numbers, kept strictly apart:

1. **Measured**: same machine, same harness. Apple M3 Pro, 18 GB, macOS 27.0.1,
   APFS, rustc 1.97.1. Every measured figure is the median of three independent
   runs (`benches/tools/run-all.sh`); raw Criterion estimates and logs are in
   `bench-results/2026-10-18/`, and `summary.txt` there lists median, min and max.
2. **Published claims**: vendor/third-party numbers for systems that cannot
   be fairly benchmarked in-process (SaaS memory APIs, server databases).
   Cited, dated, and explicitly NOT comparable to the measured latencies: they
   measure different operations on different hardware.

The paper (`paper.tex`, §8) reports the same run with more context.

## 1. Measured: neleus-db vs SQLite (same machine, same corpus)

Corpus: 10,000 text chunks (BM25), 5,000 of them with 128-dim embeddings,
10,000 KV pairs. SQLite is the macOS system build (3.54.0) through rusqlite,
file-backed with WAL and FTS5.

**Fast** configuration: neleus `durability: os`, no encryption; SQLite
`synchronous=NORMAL`. **Compliance**: neleus `durability: full`
(`F_FULLFSYNC`) with AES-256-GCM; SQLite `synchronous=FULL` + `fullfsync`.
**Barrier**: neleus `F_BARRIERFSYNC` with encryption.

| Operation | neleus fast | SQLite fast | neleus compliance | SQLite compliance |
|---|---|---|---|---|
| Point get (warm) | **0.48 µs** | 2.88 µs | | |
| BM25 top-10 | **159 µs** | 782 µs (FTS5) | | |
| Vector top-10 (HNSW, 5k × 128d) | 278 µs | n/a | | |
| Hybrid top-10 (RRF) | 457 µs | n/a | | |
| Point set, single writer | 1.47 ms | **23.6 µs** | 37.0 ms | 174 µs* |
| Point set, 8 coalesced writers (per op) | 0.75 ms | — | 12.2 ms | — |
| Point set, barrier | | | 3.5 ms | 174 µs* |
| BM25 top-10, recorded | 0.79 ms | — | 15.0 ms | — |
| Hybrid top-10, recorded | 1.08 ms | — | not measured | — |
| BM25 top-10, recorded, 8 concurrent (per search) | 0.36 ms | — | 9.2 ms | — |
| BM25 top-10, recorded, barrier | | | 3.2 ms (2.2–4.2) | — |
| Agent turn (recorded hybrid search + run commit + memory write) | 6.1 ms | — | 138 ms (113–167) | — |

\*SQLite with `fullfsync` issues `F_BARRIERFSYNC`, not a full flush, so this
cell is barrier-class. Durability syscalls per operation
(`benches/tools/sync-count.sh`):

| Operation | `F_FULLFSYNC` | `F_BARRIERFSYNC` | `fsync` |
|---|---|---|---|
| neleus state write | 8.0 | 0 | 0 |
| neleus recorded search | 4.0 | 0 | 0 |
| neleus commit, no manifests | 4.0 | 0 | 0 |
| neleus commit introducing one manifest | 15.9 | 0 | 0 |
| SQLite insert, WAL | 0 | 1.0 | 0 |
| SQLite insert, rollback journal | 0 | 3.0 | 1.0 |

Writes cost what they cost because every new tree node is a file with its own
flush; SQLite appends to one log. The coalescer shares one commit among
concurrent writers and writes each changed node once: 2.0× (fast), 2.8×
(barrier), 3.0× (compliance) over a single writer.

**Manifest index cost.** Chunk proofs are constant-size because each commit
that introduces manifests indexes them in its state. Measured on commits
introducing one chunk manifest, against commits writing the same objects but
indexing none (`commit-cost.txt`): compliance 28.1 → 55.8 ms, fast
1.12 → 2.28 ms. An empty commit costs 13.5 ms / 0.62 ms. The cost is per
commit, not per manifest.

Scale points (`cargo bench --bench scale`, fast):

| Component | Result |
|---|---|
| BLAKE3 hash-only, 101k chunks, 1 thread | 17.3 ms |
| Bulk document ingest, 100k chunks (pack-first) | **0.35 s** (~3.5 µs/chunk) |
| Per-chunk-manifest ingest, 10k chunks with 1536d embeddings | 8.4 s (~0.84 ms/chunk) |
| BM25 index build, 100k chunks | 1.76 s |
| HNSW build, 10k × 1536d (SQ8, batched parallel) | 3.29 s |
| BM25 top-10 over 100k chunks (synthetic, dense-corpus worst case) | 1.50 ms |
| Vector top-10, 10k × 1536d (SQ8 traversal, f32 rerank) | 421 µs |

Retrieval on public datasets (`cargo bench --bench datasets`, data from
`benches/tools/fetch-datasets.sh`):

| BEIR dataset | nDCG@10 neleus | nDCG@10 FTS5 | p50 neleus | p50 FTS5 |
|---|---|---|---|---|
| SciFact (5.2k docs) | 0.664 | 0.668 | 118 µs | 5.7 ms |
| FiQA (57.6k docs) | 0.232 | 0.234 | 1.10 ms | 51.9 ms |

| NYTimes-256 (290k, ANN-Benchmarks) ef | 40 | 80 | 160 | 320 | 640 |
|---|---|---|---|---|---|
| recall@10 | 0.714 | 0.792 | 0.852 | 0.897 | 0.925 |
| p50 latency | 0.46 ms | 0.74 ms | 1.24 ms | 2.26 ms | 4.54 ms |

The default beam (ef = 96 for top-10) gives recall@10 ≈ 0.80 on NYTimes; the
tests' recall ≥ 0.90 floor holds on synthetic vectors. Raise ef where recall
matters.

Notes:

- Vector and hybrid have no SQLite row because stock SQLite has no ANN index.
- Hybrid runs both modalities on separate threads over immutable segments.
- 1536d is the realistic embedding size; HNSW construction and traversal use
  SQ8 codes at ≥ 256 dims, with f32 reranking of an oversampled candidate set.

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
holds plaintext in-process, so warm reads (the 0.48 µs path) pay zero
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
  hop in production). The measured neleus path is in-process: 278 µs at
  128d, 421 µs at 1536d, zero hops. For agent loops where retrieval sits
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
| Letta (MemGPT) | DMR 93.4%; LoCoMo 74.0% using **plain filesystem storage** (their point: these benchmarks are harness-dominated) | LangMem comparison point: p50 17.99 s, p95 59.82 s ("impractical") | letta.com |

Read the LOCOMO column with suspicion: the same system scored 84%, 75.14%,
58.44%, and 80% depending on who configured the harness, which categories
were counted (Category 5 lacks ground truth), single vs 10-run averaging,
and sequential vs parallel ingestion. Both vendors concede the dataset has
quality problems. LongMemEval is the most discriminating public benchmark
(Atlan's independent run: Zep 63.8 / Mem0 49.0, far below both vendors'
self-reported numbers); DMR is saturated (Zep's own full-context baseline
hits 94.4%). Latency claims measure different operations (end-to-end answer
vs search-only vs recall-only) and are not mutually comparable.

neleus-db is a storage/retrieval engine, not a memory pipeline: it does not
call an LLM, so LOCOMO/LongMemEval scores do not apply directly. Its raw
retrieval latencies (hundreds of microseconds hybrid, in-process) sit 3–4
orders of magnitude below the sub-second pipeline latencies above, so the
storage layer is not the bottleneck of any of those pipelines. A LongMemEval
harness over neleus retrieval is the right next experiment to publish.

## 3. The verifiability gap

Documented capability check across the agent-memory market (June 2026, from
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
finds none offer cryptographic verifiability, and proposes, as a research
prototype, a **Merkle-DAG provenance structure with BLAKE3 content-addressing
and Ed25519 root signing**: the architecture neleus-db ships today.
SuperLocalMemory (arXiv 2603.02240) adds per-memory provenance
tracking against memory poisoning, also research-only. Zep's SOC 2 (access
auditing) and Cognee's air-gap option (isolation) are the closest shipping
features; neither is verification. No shipping product combines fast hybrid
retrieval with cryptographic verifiability. That combination is what this
engine provides.

## 4. Measured: proof size and verification time

`cargo bench --bench state` (fast configuration, median of three runs).

| Artifact | Size | Generate | Verify (offline) |
|---|---|---|---|
| State inclusion proof (100 keys) | 1.8–2.8 KB | 4.0 µs | **9.0 µs** |
| State non-inclusion proof (100 keys) | 0.6–2.7 KB | 0.8 µs | **4.6 µs** |
| Chunk proof (content included) | 8.7 KB | 411 µs | **21 µs** |
| Audit bundle (64 retrievals, unsigned) | 164 KB | 3.50 ms (export) | **1.10 ms** |
| Audit bundle (64 retrievals, signed bundle + checkpoint) | 167 KB | | 1.2–1.5 ms |

- **State proofs** are one root-to-leaf path. Their size depends on tree
  shape, which each database's secret determines: over 60 fresh databases
  holding the same 1,000 keys, one key's proof ranged from 1.2 to 13.8 KB
  (median ~4 KB, depth 2–4).
- **Chunk proofs** are one commit plus one state path to the manifest's
  `__manifests__/` index key: 1.6 KB after 0, 100 or 1,000 searches and after
  100 or 1,000 later writes. The previous ancestry-walking format reached
  46.8 KB and 457 KB after 100 and 1,000 writes.
- **Verification is offline**: no database, no network.

## 5. Measured: auditor-side cost and the tenant channel

`cargo bench --bench verifiability` (fast configuration, median of three runs).

| Chain length J | 1 | 10 | 100 | 1,000 | 10,000 |
|---|---|---|---|---|---|
| Walk the checkpoint chain | 43 µs | 426 µs | 4.4 ms | 50 ms | **558 ms** |

No verifier walks the chain: against a 10,000-checkpoint log an inclusion
proof is 956 B (2.6 µs) and a consistency proof 5,000 → 10,000 is 826 B
(2.9 µs). Appending a checkpoint costs ~0.8 ms.

| Retrievals R | 1 | 8 | 64 | 512 |
|---|---|---|---|---|
| Bundle bytes | 3,493 | 21,882 | 169,090 | 1,347,552 |
| Per retrieval | 3,493 B | 2,735 B | 2,642 B | **2,632 B** |
| In-process verify | 40 µs | 161 µs | 1.13 ms | 8.83 ms |
| Cold `neleus-verify` process | 24.9 ms* | 2.48 ms | 3.52 ms | 11.7 ms |

\*includes the binary's first load. Extrapolated: 1M retrievals ≈ 2.5 GiB and
≈ 17 s to verify. A 1,000-key state proof verifies store-free in 26–31 µs,
against 78–109 ms through a freshly opened database.

**Tenant channel.** With segment-wide BM25 statistics a tenant could recover
another tenant's corpus size and term counts exactly from its own scores.
Statistics are now scoped to the caller, and tenant queries read only their
tenant's own postings. A tenant's filtered BM25 query (1,000 own documents)
takes 41.4–42.8 µs whether another tenant holds 0, 10,000 or 100,000
documents (30 batches × 200 queries, three runs). A permutation test still
separates 0 from 100,000 (p ≤ 0.0001, ~1% faster with the larger corpus) but
not consistently 10,000 from 100,000 (p = 0.03, 0.22, 0.10). Before
per-tenant postings the same query went from 31–36 µs to 59–98 µs.

## 6. Adversarial evaluation

`cargo test --test adversarial -- --nocapture --test-threads=1`. Twelve
attacks by an operator that controls storage and serving code; outcomes are
asserted, including the one that succeeds.

| Attack | Detected | By |
|---|---|---|
| Forge a commit into an anchored log | yes | log root |
| Replay a log proof at another index | yes | index bound into the proof |
| Rewrite history below an anchor | yes | consistency proof |
| Truncate the log | yes | root mismatch |
| Show two verifiers divergent histories | if anchors compared | anchor comparison |
| Withhold a record from a bundle | yes | sequence gap |
| **Serve retrievals, record none** | **no** | an empty log is a valid log |
| Swap content into a chunk proof | yes | blob hash |
| Graft another state's path onto a chunk proof | yes | state root |
| Replay a state proof at another root | yes | root bound into the proof |
| Claim a present key is absent | yes | leaf inspection |
| Reattach erased content | yes | erasure flag |

Seeded tamper injection (200 trials per class, 25 records, anchor after
record 20): every edit, drop (including the oldest records of a window),
duplicate, swap, truncation, or re-chain at or below the anchor's pin is
rejected; changes confined to records after the anchor are accepted, as in
any anchored log; the untouched control never alarms.

## History: defects these benchmarks found

- Write benchmarks once rewrote existing keys and measured almost nothing.
- BM25 statistics were segment-wide, leaking other tenants' corpus statistics;
  then shared posting lists leaked their size through timing.
- Selective filters degenerated HNSW into a near-full scan.
- `gc --prune` swept the unreferenced checkpoint log.
- A gapless record chain did not reveal a truncated tail, and an exporter
  could drop a window's oldest records or choose a window that skipped the pin.
- Merkle roots did not fix their leaf count.
- Chunk proofs grew ~467 B per write since the chunk was introduced.
- Batched state writes into a non-empty tree persisted every key's path,
  turning a 10,000-key setup into 45+ minutes of flushes (now 2.9 s).

## Reproducing

```bash
benches/tools/run-all.sh bench-results/<date> 3      # every configuration, 3 runs
python3 benches/tools/summarize.py bench-results/<date>
benches/tools/sync-count.sh                          # durability syscalls per op
benches/tools/fetch-datasets.sh <dir>                # BEIR + ANN-Benchmarks data
NELEUS_BENCH_DATA=<dir> cargo bench --bench datasets
cargo test                                           # 356 tests
```

Run on an otherwise idle machine, one suite at a time.
