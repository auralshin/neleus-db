# Contributing

Thanks for taking the time. A few things that will save you (and the review)
a round trip.

## License of contributions

neleus-db is source-available under [PolyForm Noncommercial 1.0.0](LICENSE).
By submitting a contribution you license it under the project license and grant
the maintainer the right to offer it under other terms (e.g. commercial
licenses). Don't submit code you can't license this way.

## The one rule that matters: don't break the byte format

The canonical plane is a trust anchor. These are hashed into object
identities, so a change to how they serialize silently invalidates every
existing database and every proof:

- `src/canonical.rs` — DAG-CBOR encoding, golden-byte tests
- hash domains in `src/hash.rs` (`blob:`, `manifest:`, `commit:`,
  `state_node:`, `checkpoint:`, `state_leaf:`, `merkle_node:`,
  `commit_payload:`, `checkpoint_payload:`)
- on-disk shapes of `Commit`, `StateSegment`/`StateManifest`, the manifest
  types, `Checkpoint`, and the encryption envelope

If you change any of these, you are changing the format. That needs a schema
version bump and an explicit decision — open an issue first. The golden
tests in `canonical.rs` exist to fail loudly when this happens by accident;
do not "fix" them by updating the expected bytes without understanding why.

This project has no deployed users yet, so we **replace** old formats rather
than carry migration shims (e.g. PBKDF2 → Argon2id was a straight swap, not a
compat path). Greenfield until stated otherwise — don't add backward-compat
layers.

The serving plane (`src/engine/`, `src/index`-derived data) is the opposite:
it's rebuildable from canonical data and never hashed into identity, so it's
free to change. Optimize it freely; just keep recall pinned (see below).

## Before you open a PR

```bash
cargo test            # all of it must pass — no exceptions
cargo clippy          # zero warnings; CI treats them as errors
cargo fmt
```

For changes to the retrieval engine, the recall oracle tests
(`engine::vector`, `engine::segment`) must still hold — HNSW recall@10 ≥ 0.90
against the exact brute-force oracle, on both the f32 and SQ8 paths. If you
touch indexing, run the benchmarks and note any regression:

```bash
cargo bench --bench compare_sql
cargo bench --bench scale
```

## Style

- Match the surrounding code. Comments are dev-style: one line, telegraphic,
  only where the *why* isn't obvious. No narrative blocks, no restating what
  the code says.
- Errors use `anyhow` with `with_context`; surface the path/hash that failed.
- No new heavy dependencies in the canonical plane. The serving plane and
  server can take well-justified deps, but the bar is high — most of this
  (HNSW, the HTTP server, the HTTP client) is hand-rolled on purpose.
- Crypto is the exception: never hand-roll it. Use the RustCrypto / dalek
  crates already in the tree.

## Security-sensitive changes

Anything touching encryption, signing, auth, the WAL, or the proof/verify
paths gets extra scrutiny. Call it out in the PR description, explain the
threat model you're addressing, and add a test that fails without your fix.
If you find a vulnerability, please don't open a public issue — email the
maintainer first.

## Tests are part of the change

Every behavioral change ships with a test. Bug fixes ship with a test that
reproduces the bug first. "It works on my machine" is not a test.

## Scope

Keep PRs focused. One concern per PR. If you notice unrelated dead code or a
nearby cleanup, mention it — don't fold it in.
