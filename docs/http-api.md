# HTTP API

`neleus-db serve` exposes the engine over HTTP/1.1.

```bash
neleus-db --db ./db auth add-key --id app --role admin   # token printed once
neleus-db --db ./db serve --addr 127.0.0.1:7117
```

- Binds loopback by default. Non-loopback needs `--allow-remote` and minted
  keys. No in-process TLS; terminate TLS in a reverse proxy.
- Auth is required unless `--no-auth` (loopback only).
- `--cors-origin <origin>` enables CORS; preflight skips auth.
- Limits: headers 64 KiB (sent within 30 s), JSON body 8 MiB, pack upload
  4 GiB, `top_k` at most 1000, 256 connections.

## Console

Non-`/v1/*` GETs serve the embedded console. On loopback the server injects a
per-process bootstrap admin token, accepted only from loopback peers
(`--no-bootstrap` disables it). Builds without assets serve a "not bundled"
note at `/`.

## Auth

`Authorization: Bearer nlk_...`. Roles: `reader < writer < admin`. Keys are
reloaded per request, so revocation is immediate.

Tenant keys (`auth add-key --tenant acme`):

- may only name heads under `acme/`;
- have every search filter forced to `tenant = acme`;
- cannot use routes marked "untenanted" below.

## Conventions

- Time fields are unix seconds. Binary fields (`key`, `value`, `proof_cbor`)
  are base64.
- `head` names a head. History reads also accept a 64-hex commit hash, except
  `/v1/search`, where `at` must be a head and a past commit goes in `commit`.

## Routes

### Health and refs

- `GET /v1/health` (any key): `{ ok, version }`
- `GET /v1/refs` (reader, untenanted): `{ heads: [{ name, commit }], checkpoints: [{ name, checkpoint }] }`

### Documents, commits, runs (writer)

- `POST /v1/documents`: `{ head, source, text, chunk_size?, overlap?, metadata? }` -> `{ manifest, commit }`
- `POST /v1/commits`: `{ head, message, manifests? }` -> `{ commit }`
- `POST /v1/runs`: see below -> `{ manifest, commit }`

`documents`: `chunk_size` default 512, minimum 64; `overlap` default
`min(64, chunk_size / 2)`, maximum `chunk_size / 2`. `metadata` is
`{ tenant?, doc_type?, language?, valid_from?, valid_to?, expires_at?, acl?[], subject? }`;
a tenant key overrides `tenant`.

`runs` fields: `head`, `model` (required); `prompt?`, `system_prompt?`,
`model_parameters?` (object), `inputs?[]`, `outputs?[]`,
`retrieved_chunks?[]` (hashes), `provider?`, `sdk_version?`, `agent_id?`,
`trace_id?`, `parent_span?` (run manifest hash), `delegated_from?`,
`subject?`, `started_at?`, `ended_at?` (default now), `commit?` (bool,
default true; `false` returns `commit: null`), `message?` (default
`"<model> run"`).

### Blobs

- `POST /v1/blobs` (writer): raw bytes -> `{ hash }`
- `GET /v1/blobs/<hash>` (reader, untenanted): raw bytes

Tenant-key uploads are salted in the tenant namespace.

### State

- `POST /v1/state/get` (reader): `{ head, key }` -> `{ root, value }` (`value` null if absent)
- `POST /v1/state/set` (writer): `{ head, key, value }` -> `{ root }`
- `POST /v1/state/delete` (writer): `{ head, key }` -> `{ root }`
- `POST /v1/state/prove` (reader): `{ head, key }` -> `{ root, proof_cbor }`

### Search and proofs (reader)

- `POST /v1/search`: `{ at, commit?, mode?, query?, embedding?, top_k?, filter? }` -> `{ commit, hits: [{ chunk, score, preview }], audit_manifest }`
- `POST /v1/proofs/chunk`: `{ commit, chunk, include_content?, head?, anchor_head? }` -> `{ proof_cbor }`
- `POST /v1/proofs/verify`: `{ proof_cbor }` -> `{ valid, anchor, checkpoint }` or `{ valid: false, error }`

`search`:

- Always recorded on `at`; `audit_manifest` is the record hash.
- `commit` must be in the history of `at`.
- `mode`: `semantic` (needs `query`), `vector` (needs `embedding`), `hybrid`
  (default).
- `top_k` default 10.
- `filter`: `{ tenant?, doc_type?, language?, acl?[], at? }`.

`proofs/chunk`:

- `anchor_head` adds inclusion in that head's latest checkpoint.
- Tenant keys must pass `head` (or `anchor_head`), and `commit` must be in
  that head's history.
- Tenant keys cannot use `include_content`.

### Sessions and checkpoints

- `POST /v1/sessions/append` (writer): `{ head, session_id, content, role?, ttl_secs? }` -> `{ seq, content_hash }`
- `POST /v1/sessions/list` (reader): `{ head, session_id, at? }` -> `{ turns: [{ seq, role, created_at, expires_at, content }] }`
- `POST /v1/checkpoints` (writer): `{ head }` -> `{ checkpoint }`

`sessions/list` hides turns expired at `at` (default now).

### Audit

- `GET /v1/compliance/summary` (reader, untenanted): `{ generated_at, heads[], encryption_enabled, retention_min_secs }`
- `POST /v1/audit/queries` (reader): `{ head, from?, to? }` -> `{ head, from, to, records[] }`
- `POST /v1/audit/export` (reader): `{ head, from?, to?, anchor? }` -> bundle bytes

Each `heads[]` entry: `{ name, commit, chain, retrievals_30d, principals_30d, last_retrieval_at }`.
`anchor` is a retained checkpoint hash; the bundle adds a consistency proof
from it.

Bundles are signed only when the server runs with `--sign-key <seed>`.
Unsigned bundles carry only an unkeyed BLAKE3 footer, which an editor can
recompute.

### Replication (admin, untenanted)

- `GET /v1/pack`: pack bytes for the whole DB
- `POST /v1/pack`: pack bytes -> `{ objects_added, packs_copied, refs_updated, refs_skipped, checkpoints_updated }`

Uploads merge fast-forward only.

### Erasure (untenanted)

- `POST /v1/erasure` (admin): `{ subject, reason? }` -> the erasure record
- `GET /v1/erasure` (reader): `{ records[] }`

`reason`: `request` (default), `ttl`, `account-closure`. Content is shredded;
commit hashes stay intact. The record is signed with the server's audit
signing key when `--sign-key` is set.

### Policy and events (untenanted)

- `GET /v1/policy` (reader): `{ policy }` (`webhook` hidden from non-admins)
- `POST /v1/policy` (admin): a `PolicySet` (replaces the set) -> `{ policy }`
- `POST /v1/policy/evaluate` (reader): `{ head? }` -> `{ generated_at, pass, warn, fail, statuses[] }`
- `GET /v1/events` (reader): `?since=<seq>`, `?wait=<secs>` (max 30), `?verify=1` -> `{ events[], chain_verified? }`

`chain_verified` appears only with `?verify=1`; it walks the whole log.

`enforce` policies gate the write routes (`documents`, `runs`, `commits`,
`blobs`, `state/set`, `state/delete`, `sessions/append`, `checkpoints`,
`pack`) and `search`. A blocked write returns 403 `policy_violation` and is
logged. See [policy.md](policy.md).

## Errors

Body: `{ error, code, hint? }`. Branch on `code`.

| HTTP | `code` | Cause |
|---|---|---|
| 400 | `bad_request` | Malformed body or value. |
| 401 | `unauthorized` | Missing or invalid token. |
| 403 | `forbidden` | Role or tenant not permitted. |
| 403 | `policy_violation` | Blocked by an `enforce` policy. |
| 404 | `not_found` | No such head, commit, or route. |
| 408 | `request_timeout` | Headers not complete within 30 s. |
| 413 | `payload_too_large` | Body over the limit. |
| 431 | `headers_too_large` | Headers over 64 KiB. |
| 503 | `overloaded` | Connection cap reached. |
| 5xx | `internal` | Server error. |
