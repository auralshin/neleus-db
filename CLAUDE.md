# Repository Instructions

## Project

neleus-db is a local-first, content-addressed (Merkle-DAG) database for AI
agents: cryptographic proofs, immutable versioning, retrieval audit, and a
policy engine that monitors and enforces compliance rules at write time. The
server is std-only HTTP (no async runtime, no in-process TLS) and `serve`
bundles a web console into the binary.

Key modules: `src/engine/` (BM25 + vector retrieval), `src/state.rs` (state +
proofs), `src/commit.rs` / `src/manifest.rs` (commits, manifests),
`src/server.rs` (HTTP + embedded console), `src/policy.rs` (policy-as-code +
enforcement), `src/events.rs` (tamper-evident event log), `src/audit.rs`
(retrieval records, audit bundles), `src/checkpoint.rs` + `src/merkle.rs`
(checkpoint log with RFC 6962 roots), `src/cas.rs` (content-addressed object
files), `src/sync.rs` (replication). UI source in `console/`, SDKs in
`sdk/{python,typescript,rust,python-native}`. `tests/adversarial.rs` pins what
verification detects, including seeded tamper-injection trials.

## Invariants

- The server and CLI record every search on a head; there is no opt-out. A
  past commit is searched with `commit` (HTTP) / `--at` (CLI), still recorded
  on the head. Library callers record too via `Engine::search`; only the
  explicit `search_*_unrecorded` methods skip it.
- The retrieval chain tip is derived from the commit graph
  (`audit::query_tip`, memoized per commit); there is no query ref. Records
  carry a gapless `seq` + `prev`; each checkpoint pins the newest record
  (`query_tip`) so the bundle verifier catches truncation below an anchor.
- One per-database `secret` in `meta/config.json` derives the state-tree
  boundary key and the blob salt keys. Replicas must share it: create them
  with `db init --replica-of <url>`; merges with different secrets are refused.
- Blobs are stored as `salt || content`; the id hashes the whole payload and
  the salt is keyed by the head's namespace (`BlobStore::for_head`), so ids
  differ across tenants and cannot be confirmed from content alone. Proofs
  carry the payload; `ChunkProof::chunk_content` strips the salt.
- Concurrent recordings on a head group-commit (`engine/recorder.rs`).
- Audit bundles carry only the latest checkpoint; `--anchor` adds a
  consistency proof from a retained checkpoint. Chunk proofs can carry an
  inclusion anchor (`prove_chunk_anchored`).
- Tenant-scoped vector queries use the tenant's own graph or an exact scan,
  never the shared graph.
- Durability (`os` | `full`, default `full`) is process-wide, set at
  `Database::open`. CAS objects publish with a no-replace rename (hard-link
  fallback); head and staging refs are `write_atomic` without WAL; checkpoint
  refs keep WAL.
- BM25 statistics are scoped to what the caller may see.
- Unit tests skip fsync (`cfg!(test)` in `atomic.rs`); the lib suite runs in
  about 20 s.

## Commands

- Build: `cargo build` (the default `console` feature embeds `console/dist`).
- Test: `cargo test` (lib units + `tests/` integration).
- Build the console UI: `npm --prefix console ci && npm --prefix console run build`.
- Run: `cargo run -- db init ./db` then `cargo run -- --db ./db serve --open`.
- Lint/format: `cargo fmt`, `cargo clippy`.
- Node-less / API-only build: `cargo build --no-default-features`.
- Adversarial + tamper report: `cargo test --test adversarial -- --nocapture --test-threads=1`.
- Benchmarks (`os`): `NELEUS_BENCH_DURABILITY=os cargo bench --bench compare_sql --bench state --bench scale --bench verifiability`.
- Benchmarks (compliance: fsync + encryption, writes only):
  `NELEUS_BENCH_DURABILITY=full NELEUS_BENCH_ENCRYPT=1 NELEUS_BENCH_WRITES_ONLY=1 cargo bench --bench compare_sql --bench scale -- 'point_set|semantic_recorded|coalesced' --warm-up-time 1 --measurement-time 3 --sample-size 10`.

## Scope

These instructions apply to the whole repository unless a more specific
`AGENTS.md` exists in a subdirectory.

## Hard Rules

- Greenfield: no backward-compatibility shims or format migrations. Replace old
  formats outright.
- Comments are terse and one-line. No narrative docstrings, no usage examples in
  comments, no "like library X" comparisons. Document only the non-obvious why.

## Change Discipline

- Make the smallest change that satisfies the request.
- Do not solve assumed issues. If a problem is adjacent but not requested,
  report it separately instead of changing behavior.
- Do not leave TODOs, stubs, placeholder behavior, or partial implementations
  unless the user explicitly asks for them. If something cannot be completed,
  say what is incomplete and why.
- Preserve existing public behavior unless the requested change requires
  changing it.
- Prefer existing local patterns over new abstractions.
- Avoid broad formatting, renames, or refactors unless they are necessary for
  the requested work.

## Build And Generated Files

- Build scripts should be deterministic and quiet on success.
- Use `cargo:warning` only for actionable build problems, not normal status
  reporting.
- Generated files must clearly identify their generator and should not require
  manual edits.
- Do not require Node, npm, network access, or external tools during a Rust
  build unless the feature or command being used explicitly requires them.
- If a feature depends on prebuilt assets, degrade clearly when assets are
  missing and document the command needed to produce them.
- Prefer build-time work only when it reduces runtime dependencies, startup
  cost, or packaging complexity.

## Comments And Documentation

- Comments should explain invariants, non-obvious constraints, or tradeoffs.
- Do not comment obvious code.
- Keep file headers short. Prefer targeted comments near the code that needs
  context.
- Remove stale comments when behavior changes.
- Avoid marketing language, vague claims, and duplicated explanations.

## Code Minimalism

- Keep functions and data structures direct unless an abstraction removes real
  duplication or makes an invariant clearer.
- Prefer explicit errors over silent fallback when a failure would hide corrupt
  inputs, missing files, or an incomplete build.
- Avoid adding dependencies unless they materially simplify the implementation
  or improve correctness.
- Keep configuration surface small. Add options only when there is a real user
  need.

## Verification

- Run the narrowest useful check for the files changed.
- For Rust changes, prefer `cargo check` and targeted tests before broader test
  suites.
- If a repo-wide formatter or test suite fails because of unrelated existing
  issues, do not fix them opportunistically. Report the failure and the relevant
  unrelated scope.

## Working rules

- Read the code paths a change touches before editing; confirm the fix fits
  existing invariants (durability, CAS, sequence chains) instead of probing by
  trial runs.
- Fix first, then verify once: targeted tests for the changed module, then the
  full suite a single time. Do not re-run suites between small edits.
- Benchmarks: run only what a cited number needs (Criterion name filters);
  reads do not change with fsync, so compliance runs cover writes and recorded
  searches only. Set durability from init, never mid-process. Re-run a suite
  only if code it exercises changed. One run at a time, idle machine, no edits
  while a suite runs.

## Benchmarks

- Run only what a cited number needs. Use Criterion name filters, e.g.
  `cargo bench --bench compare_sql -- 'point_set|recorded'`.
- Two configurations: `os` (default runs) and compliance
  (`NELEUS_BENCH_DURABILITY=full NELEUS_BENCH_ENCRYPT=1`). Reads do not change
  with fsync, so compliance runs cover writes and recorded searches only.
- Compliance runs add `NELEUS_BENCH_WRITES_ONLY=1` (skips index builds, uses
  pack-first setup) and short timing:
  `--warm-up-time 1 --measurement-time 3 --sample-size 10`.
- Set durability from init (`benches/common`); do not switch it mid-process.
- Re-run a suite only if code it exercises changed; one `cargo bench`
  invocation per mode (`--bench a --bench b`).
- Benchmark one run at a time on an otherwise idle machine; never edit code
  while a suite is running.
