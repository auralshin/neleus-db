# Security

## Threat model

- **Disk thief**: encryption at rest.
- **Network attacker**: a TLS proxy in front of `serve` (none built in).
- **Other tenant**: tenant-pinned keys.
- **Insider rewriting history or dropping records**: detectable through signed
  commits, checkpoints, and offline proofs, if the verifier holds a checkpoint
  hash or public key from outside the database.
- **Abusive client**: body limits (8 MiB JSON), 256 connections, `top_k` ≤ 1000.

## Encryption at rest

Enable with `"encryption": {"enabled": true, "algorithm": "aes-256-gcm"}` in
`meta/config.json` (or `chacha20-poly1305`) and set
`NELEUS_DB_ENCRYPTION_PASSWORD`. Opening fails if the password is missing.

- The master key is Argon2id (19 MiB, t=2, p=1) over the password and a random
  `master_salt` stored in config. Each write gets a fresh salt and nonce and a
  one-time HKDF-SHA256 key.
- Encrypted: blobs, objects (manifests, state, commits, checkpoints), and index
  files.
- Not encrypted: `refs/` and `wal/` (ref names, hashes, key lengths),
  `meta/events.jsonl` (policy violations and erasure records, including subject
  ids), `meta/policy.json`, `meta/auth.json` (token hashes only), and
  `meta/config.json`, which holds the database `secret`. Head names (tenant
  names) appear in file paths. Use full-disk encryption if these matter.
- `db reencrypt` re-encrypts everything under a new password
  (`NELEUS_DB_NEW_ENCRYPTION_PASSWORD`).
- Keys and passwords are zeroized on drop; plaintext returned to callers is not.

## Transport

`serve` has no TLS. It binds loopback by default. A non-loopback bind needs
`--allow-remote` and configured keys (`--no-auth` is refused). Put a TLS proxy
in front for any real network.

## Auth and tenancy

- Tokens are `nlk_<hex>` 32-byte secrets minted with `auth add-key` (CLI
  only). Only the BLAKE3 hash is stored (`meta/auth.json`, mode 0600) and
  compared in constant time. Keys reload per request, so revocation is
  immediate.
- Roles: `reader < writer < admin`.
- A tenant key (`--tenant acme`) may only name heads under `acme/`, its
  searches are forced to `tenant=acme`, and its blob uploads are salted in the
  `acme` namespace. It cannot use untenanted routes (raw blob reads, refs,
  packs, policy, events, erasure, compliance summary). Its chunk proofs must
  name a head under its prefix, prove a commit in that head's history, and omit
  content.
- Tenant vector queries use the tenant's own graph or an exact scan, never a
  shared graph.
- ACL tags filter chunks within a tenant before scoring: an empty chunk ACL is
  public, otherwise the request needs a matching tag. The tags come from the
  request's `filter.acl`, not from the key, so ACLs are a retrieval filter for
  a trusted caller, not an access boundary between keys.

## Tamper evidence

See [concepts.md](concepts.md#verifiability) for the mechanisms. Limits:

- Commits are signed only when a signer is set (`commit new --sign-key`,
  `serve --sign-key`, `Engine::set_commit_signer`). Checkpoints are signed only
  by `checkpoint new --sign-key` or the library, never over HTTP.
- Anyone with write access to the directory can rebuild an unsigned chain (or
  a signed one, if the key sits on the same host), so keep a checkpoint hash
  or public key outside the database.
- An unsigned audit bundle shows corruption, not edits by whoever exported it.

## Durability

Set `durability` in `meta/config.json`; it applies process-wide from open.

- `full` (default): file and directory sync per write, `F_FULLFSYNC` on macOS.
  Writes survive power loss once acknowledged.
- `barrier`: `F_BARRIERFSYNC` on macOS (keeps write order, may lose the newest
  writes on power loss). Full sync elsewhere.
- `os`: no sync. Survives a process crash, not power loss.

In every mode objects publish by atomic rename and torn objects fail their
hash, so weaker modes lose recent writes, not integrity.

## Reporting

Report vulnerabilities privately to the maintainer, not in a public issue. See
[../CONTRIBUTING.md](../CONTRIBUTING.md).
