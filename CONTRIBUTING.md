# Contributing

## License

Contributions are dual-licensed under [Apache-2.0](LICENSE-APACHE) and
[MIT](LICENSE-MIT) unless you state otherwise. Submit only code you can
license this way.

## Byte format

These are hashed into object identities. Changing how they serialize breaks
every existing database and proof:

- `src/canonical.rs`: DAG-CBOR encoding and golden-byte tests.
- Hash domains in `src/hash.rs` (`blob:`, `manifest:`, `manifest_leaf:`,
  `state_node:`, `commit:`, `commit_payload:`, `checkpoint:`,
  `checkpoint_payload:`, `checkpoint_leaf:`, `merkle_node:`, `merkle_root:`,
  `index_segment:`).
- On-disk shapes of `Commit`, `StateNode`/`StateManifest`, the manifest types,
  `Checkpoint`, and the encryption envelope.

A format change needs a schema version bump; open an issue first. Do not
update golden bytes without knowing why they changed. Replace old formats
outright; no migration shims.

The serving plane (`src/engine/`) is rebuilt from canonical data and is free
to change, as long as recall holds.

## Commands

```bash
cargo build                    # embeds console/dist (default `console` feature)
cargo build --no-default-features   # API only, no Node needed
npm --prefix console ci && npm --prefix console run build
cargo test
cargo fmt
cargo clippy
cargo test --test adversarial -- --nocapture --test-threads=1
```

Engine changes must keep the recall tests in `engine::vector` and
`engine::segment` passing (HNSW recall@10 >= 0.90 on the f32 and SQ8 paths).
If you touch indexing, run the benchmarks you need and note regressions:

```bash
NELEUS_BENCH_DURABILITY=os cargo bench --bench compare_sql --bench state --bench scale --bench verifiability
NELEUS_BENCH_DURABILITY=full NELEUS_BENCH_ENCRYPT=1 NELEUS_BENCH_WRITES_ONLY=1 \
  cargo bench --bench compare_sql --bench scale -- 'point_set|semantic_recorded|coalesced' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs `cargo fmt --check`, the
console build, `cargo test`, `cargo build --release`, and the SDK suites
(Rust tests, Python-native check, TypeScript tests). Run `cargo clippy`
locally; CI does not run it.

## Style

- Match the surrounding code. Comments are one line, only where the why is
  not obvious.
- Errors use `anyhow` with `with_context`, naming the path or hash that failed.
- Avoid new dependencies, especially in the canonical plane.
- Never hand-roll crypto; use the RustCrypto and dalek crates already in use.

## Security

Changes to encryption, signing, auth, the WAL, or proof verification need a
note in the PR on the threat addressed and a test that fails without the fix.
Report vulnerabilities by email to the maintainer, not in a public issue.

## Pull requests

- Every behavior change ships with a test; bug fixes start with a failing test.
- One concern per PR. Mention unrelated cleanups instead of including them.
