# Benchmarks

Machine: Apple M3 Pro, 18 GB, macOS 27.0.1, APFS, rustc 1.97.1. Each figure
is the median of three runs of `benches/tools/run-all.sh`, which also writes
the raw Criterion estimates and a min/max summary. `paper.tex` §8 reports the
same run.

Configurations:

- **Fast**: `durability: os`, no encryption.
- **Compliance**: `durability: full` (`F_FULLFSYNC`) with AES-256-GCM.
- **Barrier**: `F_BARRIERFSYNC` with encryption.

Corpus: 10,000 text chunks (BM25), 5,000 of them with 128-dim embeddings,
10,000 KV pairs.

## Microbenchmarks

| Operation | Fast | Compliance |
|---|---|---|
| Point get (warm) | 0.48 µs | |
| BM25 top-10 | 159 µs | |
| Vector top-10 (HNSW, 5k × 128d) | 278 µs | |
| Hybrid top-10 (RRF) | 457 µs | |
| Point set, single writer | 1.47 ms | 37.0 ms |
| Point set, 8 coalesced writers (per op) | 0.75 ms | 12.2 ms |
| Point set, barrier | | 3.5 ms |
| BM25 top-10, recorded | 0.79 ms | 15.0 ms |
| Hybrid top-10, recorded | 1.08 ms | not measured |
| BM25 top-10, recorded, 8 concurrent (per search) | 0.36 ms | 9.2 ms |
| BM25 top-10, recorded, barrier | | 3.2 ms (2.2–4.2) |
| Agent turn (recorded hybrid search + run commit + memory write) | 6.1 ms | 138 ms (113–167) |

Reads do not depend on durability, so compliance runs cover writes and
recorded searches only. Hybrid search runs both modalities on separate
threads over immutable segments.

**SQLite reference.** For orientation only, the same corpus in the macOS
system SQLite (3.54.0, rusqlite, WAL, FTS5) on the same machine: point get
2.88 µs, FTS5 top-10 782 µs, insert 23.6 µs with `synchronous=NORMAL` and
174 µs with `synchronous=FULL` + `fullfsync`. SQLite's `fullfsync` issues
`F_BARRIERFSYNC`, so that last figure is barrier-class. Stock SQLite has no
ANN index, so it has no vector or hybrid figure.

## Durability syscalls per operation

From `benches/tools/sync-count.sh`.

| Operation | `F_FULLFSYNC` | `F_BARRIERFSYNC` | `fsync` |
|---|---|---|---|
| neleus state write | 8.0 | 0 | 0 |
| neleus recorded search | 4.0 | 0 | 0 |
| neleus commit, no manifests | 4.0 | 0 | 0 |
| neleus commit introducing one manifest | 15.9 | 0 | 0 |
| SQLite insert, WAL | 0 | 1.0 | 0 |
| SQLite insert, rollback journal | 0 | 3.0 | 1.0 |

Each new tree node is its own file with its own flush, which is why writes
cost what they do. The coalescer shares one commit among concurrent writers
and writes each changed node once: 2.0× (fast), 2.8× (barrier), 3.0×
(compliance) over a single writer.

## Manifest index cost

Each commit that introduces manifests indexes them in its state, which keeps
chunk proofs constant-size. A commit introducing one chunk manifest, against
one writing the same objects without indexing: compliance 28.1 → 55.8 ms,
fast 1.12 → 2.28 ms. An empty commit costs 13.5 ms / 0.62 ms. The cost is per
commit, not per manifest.

## Scale

`cargo bench --bench scale`, fast.

| Component | Result |
|---|---|
| BLAKE3 hash-only, 101k chunks, 1 thread | 17.3 ms |
| Bulk document ingest, 100k chunks (pack-first) | 0.35 s (~3.5 µs/chunk) |
| Per-chunk-manifest ingest, 10k chunks with 1536d embeddings | 8.4 s (~0.84 ms/chunk) |
| BM25 index build, 100k chunks | 1.76 s |
| HNSW build, 10k × 1536d (SQ8, batched parallel) | 3.29 s |
| BM25 top-10 over 100k chunks (synthetic, dense-corpus worst case) | 1.50 ms |
| Vector top-10, 10k × 1536d (SQ8 traversal, f32 rerank) | 421 µs |

At 256 dims and above, HNSW build and traversal use SQ8 codes and rerank an
oversampled candidate set in f32.

## Public datasets

`cargo bench --bench datasets`, data from `benches/tools/fetch-datasets.sh`.

| BEIR dataset | nDCG@10 | p50 latency |
|---|---|---|
| SciFact (5.2k docs) | 0.664 | 118 µs |
| FiQA (57.6k docs) | 0.232 | 1.10 ms |

The BEIR authors report 0.665 and 0.236 for BM25 on these datasets. For
reference, SQLite FTS5 with the query terms ORed scores 0.668 and 0.234.

| NYTimes-256 (290k, ANN-Benchmarks) ef | 40 | 80 | 160 | 320 | 640 |
|---|---|---|---|---|---|
| recall@10 | 0.714 | 0.792 | 0.852 | 0.897 | 0.925 |
| p50 latency | 0.46 ms | 0.74 ms | 1.24 ms | 2.26 ms | 4.54 ms |

The default beam (ef = 96 for top-10) gives recall@10 ≈ 0.80 on NYTimes.
Raise ef where recall matters.

## Proof size and verification

`cargo bench --bench state`, fast.

| Artifact | Size | Generate | Verify (offline) |
|---|---|---|---|
| State inclusion proof (100 keys) | 1.8–2.8 KB | 4.0 µs | 9.0 µs |
| State non-inclusion proof (100 keys) | 0.6–2.7 KB | 0.8 µs | 4.6 µs |
| Chunk proof (content included) | 8.7 KB | 411 µs | 21 µs |
| Audit bundle (64 retrievals, unsigned) | 164 KB | 3.50 ms (export) | 1.10 ms |
| Audit bundle (64 retrievals, signed bundle + checkpoint) | 167 KB | | 1.2–1.5 ms |

- A state proof is one root-to-leaf path. Tree shape depends on the database
  secret: over 60 fresh databases holding the same 1,000 keys, one key's proof
  ranged from 1.2 to 13.8 KB (median ~4 KB, depth 2–4).
- A chunk proof is one commit plus one state path to the manifest's
  `__manifests__/` index key: 1.6 KB after 0, 100 or 1,000 searches and after
  100 or 1,000 later writes.
- Verification needs no database and no network.

## Auditor cost

`cargo bench --bench verifiability`, fast.

| Chain length J | 1 | 10 | 100 | 1,000 | 10,000 |
|---|---|---|---|---|---|
| Walk the checkpoint chain | 43 µs | 426 µs | 4.4 ms | 50 ms | 558 ms |

Verifiers do not walk the chain. Against a 10,000-checkpoint log, an inclusion
proof is 956 B (2.6 µs) and a consistency proof 5,000 → 10,000 is 826 B
(2.9 µs). Appending a checkpoint costs ~0.8 ms.

| Retrievals R | 1 | 8 | 64 | 512 |
|---|---|---|---|---|
| Bundle bytes | 3,493 | 21,882 | 169,090 | 1,347,552 |
| Per retrieval | 3,493 B | 2,735 B | 2,642 B | 2,632 B |
| In-process verify | 40 µs | 161 µs | 1.13 ms | 8.83 ms |
| Cold `neleus-verify` process | 24.9 ms* | 2.48 ms | 3.52 ms | 11.7 ms |

\*Includes the binary's first load. Extrapolated: 1M retrievals ≈ 2.5 GiB and
≈ 17 s to verify. A 1,000-key state proof verifies store-free in 26–31 µs,
against 78–109 ms through a freshly opened database.

## Tenant timing

BM25 statistics are scoped to the caller, and tenant queries read only their
tenant's postings. A tenant's filtered BM25 query (1,000 own documents) takes
41.4–42.8 µs whether another tenant holds 0, 10,000 or 100,000 documents
(30 batches × 200 queries, three runs). A permutation test still separates 0
from 100,000 (p ≤ 0.0001, ~1% faster with the larger corpus) but not
consistently 10,000 from 100,000 (p = 0.03, 0.22, 0.10).

## Adversarial evaluation

`cargo test --test adversarial -- --nocapture --test-threads=1`. Twelve
attacks by an operator who controls storage and serving code. Each outcome is
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

Seeded tamper injection (200 trials per class, 25 records, anchor after record
20): every edit, drop (including a window's oldest records), duplicate, swap,
truncation, or re-chain at or below the anchor's pin is rejected. Changes
confined to records after the anchor are accepted, as in any anchored log. The
untouched control never alarms.

## Reproducing

```bash
benches/tools/run-all.sh bench-results/<date> 3      # every configuration, 3 runs
python3 benches/tools/summarize.py bench-results/<date>
benches/tools/sync-count.sh                          # durability syscalls per op
benches/tools/fetch-datasets.sh <dir>                # BEIR + ANN-Benchmarks data
NELEUS_BENCH_DATA=<dir> cargo bench --bench datasets
```

Run on an otherwise idle machine, one suite at a time.
