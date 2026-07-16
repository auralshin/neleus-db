# Security

The threat model first, then the control for each attacker. Security is a
plane here, not a feature list.

## Threat model

| Attacker | Capability | Controls |
|---|---|---|
| Disk thief / storage leak | Reads files at rest | AEAD on blobs, objects, index, and WAL payloads; Argon2id master key; key hygiene |
| Network attacker | Intercepts / alters traffic | TLS terminated in front; loopback-by-default server |
| Curious or malicious tenant | Crafts queries to read other tenants' data | Hard tenant partitioning; ACL prefilters |
| Compromised agent / insider | Rewrites history, forges provenance | Signed commits, checkpoint chains, offline proofs |
| Abusive client | Resource exhaustion | Bounded requests, single-writer serialization |

## At rest

- **AEAD per object** — AES-256-GCM or ChaCha20-Poly1305. Each write gets a
  fresh random salt + nonce; the per-object key is derived via
  HKDF-SHA256(master_key, salt) and used once.
- **Master key** — derived once at `open` via Argon2id (19 MiB, t=2, p=1 —
  OWASP parameters) from your password and a long-lived random `master_salt`
  persisted in `meta/config.json`.
- **Coverage** — blobs, objects, index segments, and head manifests are all
  encrypted when encryption is enabled. Filenames are content hashes; for the
  threat model this only confirms *known* plaintexts.
- **Key rotation** — `db reencrypt` re-wraps every ciphertext under a new
  password; `master_salt` is never rotated (existing ciphertext depends on
  it).
- **Memory hygiene** — passwords and derived keys are `Zeroizing`, wiped on
  drop. Decrypted plaintext escapes through callers and is the caller's
  concern.
- Decryption failure is reported identically for wrong-key and
  tampered-ciphertext — no oracle.

## In transit

No in-process TLS, on purpose — hand-rolling TLS would be the opposite of
secure. The server is loopback-only unless you pass `--allow-remote` (which
also requires configured keys). For any real network, terminate TLS with a
reverse proxy or tunnel in front. Replication and the SDK speak plain HTTP to
that proxied endpoint.

## AuthN / AuthZ / tenancy

- **Tokens** are `nlk_<hex>` 32-byte secrets. Only the BLAKE3 hash is stored
  (`meta/auth.json`, 0600); the token is shown once at mint time and never
  stored. Verification compares hashes in constant time and checks every
  stored hash (no early exit), so timing reveals nothing.
- **Roles** form a ladder: `reader < writer < admin`. The registry reloads
  per request — revocation is immediate.
- **Tenancy is structural, not a filter.** A tenant key may only name heads
  under `<tenant>/`; every search it runs is forced to its tenant filter; and
  it cannot reach the below-the-boundary endpoints (raw blobs, packs, refs).
  A cross-tenant read is unrepresentable in the API, not merely denied.
- **ACLs within a tenant** are metadata prefilters — applied before scoring,
  so a chunk the caller can't see never affects scores or timing. An empty
  chunk ACL is public within its tenant; a non-empty ACL requires an
  overlapping caller tag. Revocation is a new commit changing tags, and the
  old state stays provable — you can prove what an agent was *allowed to see
  at the time*.

## Tamper evidence

- **Content addressing** is the foundation: the name is the hash of the
  bytes, so alteration is detectable, not just discouraged.
- **Signed commits** — ed25519 over the commit's canonical payload hash. A
  verifier re-derives the payload hash and checks it matches before checking
  the signature, so mutating any field invalidates the commit.
- **Checkpoint chains** — an append-only, optionally-signed hash chain per
  head; each checkpoint commits to its predecessor. Detects history rewrites
  even by a holder of the commit signing key. Publish the latest hash
  externally to anchor everything below it.
- **Offline proofs** — chunk proofs and audit bundles verify with nothing but
  BLAKE3 + a CBOR decoder. The verifier (`neleus-verify`) is standalone.

## Durability

`durability` in config: `os` (default — no fsync; crash-of-process safe,
power loss may drop the most recent writes, SQLite WAL+NORMAL class) or
`full` (fsync file + directory per write; power-loss durable). Either way,
content addressing means a torn write is detectable and refs are
WAL-recovered — you lose recency, never integrity.

## Reporting

Found a vulnerability? Please don't open a public issue — email the
maintainer first. Security-sensitive changes (encryption, signing, auth, WAL,
proofs) get extra review and must ship with a test that fails without the
fix; see [../CONTRIBUTING.md](../CONTRIBUTING.md).
