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
enforcement), `src/events.rs` (tamper-evident event log), `src/compliance.rs`
(framework checks), `src/audit.rs` (audit bundles). UI source in `console/`,
SDKs in `sdk/{python,typescript,rust,python-native}`.

## Commands

- Build: `cargo build` (the default `console` feature embeds `console/dist`).
- Test: `cargo test` (lib units + `tests/` integration).
- Build the console UI: `npm --prefix console ci && npm --prefix console run build`.
- Run: `cargo run -- db init ./db` then `cargo run -- --db ./db serve --open`.
- Lint/format: `cargo fmt`, `cargo clippy`.
- Node-less / API-only build: `cargo build --no-default-features`.

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
