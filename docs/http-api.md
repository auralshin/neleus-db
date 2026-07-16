# HTTP API

`neleus-db serve` exposes the engine over HTTP/1.1. Same engine as embedded
use, so behavior cannot drift.

## Running

```bash
neleus-db --db ./db auth add-key --id app --role admin   # token, printed once
neleus-db --db ./db serve --addr 127.0.0.1:7117
```

- **Loopback by default.** A non-loopback bind needs `--allow-remote` *and*
  configured keys. There is no in-process TLS by design — terminate TLS with
  a reverse proxy (Caddy, nginx) in front.
- **Auth required** unless `--no-auth` (loopback-only dev escape hatch).
- **CORS** for cross-origin browser clients (e.g. the console's Vite dev
  server): `--cors-origin <origin>` (or `*` behind an authenticating proxy).
  Preflight `OPTIONS` is answered before auth. The *bundled* console is
  same-origin and needs no CORS.
- **Bounds:** headers 64 KiB, JSON bodies 8 MiB, pack uploads 4 GiB, `top_k`
  ≤ 1000, 256 concurrent connections. Single writer mutex; readers run
  concurrently against commit snapshots.

## Web console

`serve` bundles the web console into the binary and serves it same-origin at
`/` — no separate process, like a built-in admin UI. `serve --open` launches a
browser at it.

- Non-`/v1/*` GETs return the embedded SPA (with an `index.html` fallback for
  client routes); the `/v1/*` API stays authenticated.
- On a **loopback** bind the server mints a per-process **bootstrap admin
  token**, injects it into the served page, and accepts it only from loopback
  peers — so `serve --open` on localhost just works with zero key setup.
  `--no-bootstrap` disables it; remote binds always require minted keys.
- Built with `--no-default-features` (or when `console/dist` is absent) the
  binary still runs and serves the API; `/` returns a short "not bundled" note.

## Auth

Send `Authorization: Bearer nlk_…`. Roles form a ladder: `reader < writer <
admin`. The registry is reloaded per request, so revocation is immediate.

**Tenant keys** (`auth add-key --tenant acme`) are a hard partition, not a
filter: they may only name heads under `acme/`, every search is forced to
`filter.tenant = acme`, and the below-the-boundary endpoints (`/v1/blobs`,
`/v1/pack`, `/v1/refs`) are unreachable.

## Routes

`at` accepts a head name or a 64-hex commit hash (time-travel). Time fields
are unix seconds.

### Health and refs

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/v1/health` | any (still authed) | `{ ok, version }` |
| GET | `/v1/refs` | reader, untenanted | heads + checkpoint tips |

### Documents, commits, runs

| Method | Path | Role | Body |
|---|---|---|---|
| POST | `/v1/documents` | writer | `{ head, source, text, chunk_size?, overlap?, metadata? }` → `{ manifest, commit }` |
| POST | `/v1/commits` | writer | `{ head, message, manifests? }` → `{ commit }` |
| POST | `/v1/runs` | writer | `{ head, model, prompt?, system_prompt?, model_parameters?, inputs?, outputs?, retrieved_chunks?, provider?, agent_id?, trace_id?, parent_span?, delegated_from?, commit? }` → `{ manifest, commit }` |

`trace_id` groups runs of one task across agent handoffs and model switches;
`parent_span` is the parent run's manifest hash (a verifiable span edge, 64-hex
or 400); `delegated_from` is the agent that handed off. Each run also records its
*declared* model/provider — the audited claim, not a cryptographic attestation of
the remote model.

### Blobs (untenanted)

| Method | Path | Role |
|---|---|---|
| POST | `/v1/blobs` | writer, untenanted — body is raw bytes → `{ hash }` |
| GET | `/v1/blobs/<hash>` | reader, untenanted — returns raw bytes |

### State

| Method | Path | Role | Body |
|---|---|---|---|
| POST | `/v1/state/get` | reader | `{ head, key }` (base64 key) → `{ root, value }` |
| POST | `/v1/state/set` | writer | `{ head, key, value }` (base64) → `{ root }` |
| POST | `/v1/state/delete` | writer | `{ head, key }` |
| POST | `/v1/state/prove` | reader | `{ head, key }` → `{ root, proof_cbor }` |

### Search and proofs

| Method | Path | Role | Body |
|---|---|---|---|
| POST | `/v1/search` | reader | `{ at, mode, query?, embedding?, top_k?, filter?, audit? }` → `{ commit, hits[], audit_manifest? }` |
| POST | `/v1/proofs/chunk` | reader | `{ commit, chunk, include_content? }` → `{ proof_cbor }` |
| POST | `/v1/proofs/verify` | reader | `{ proof_cbor }` → `{ valid, anchor? \| error }` |

`mode` is `semantic` | `vector` | `hybrid`. `filter` is
`{ tenant?, doc_type?, language?, acl?[], at? }`.

### Sessions and checkpoints

| Method | Path | Role | Body |
|---|---|---|---|
| POST | `/v1/sessions/append` | writer | `{ head, session_id, content, role?, ttl_secs? }` |
| POST | `/v1/sessions/list` | reader | `{ head, session_id, at? }` → `{ turns[] }` |
| POST | `/v1/checkpoints` | writer | `{ head }` → `{ checkpoint }` |

### Audit

| Method | Path | Role | Body / notes |
|---|---|---|---|
| GET | `/v1/compliance/summary` | reader, untenanted | per-head chain status, retrievals, encryption, retention |
| POST | `/v1/audit/queries` | reader | `{ head, from?, to? }` → `{ records[] }` |
| POST | `/v1/audit/export` | reader | `{ head, from?, to? }` → bundle bytes (octet-stream) |

Server-side export carries the integrity footer (tamper-evident,
offline-verifiable). Origin **signing** is a CLI/KMS operation —
`neleus-db audit export --sign-key` — so a signing key never has to live in
the server.

### Replication (untenanted, admin)

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/pack` | download the whole DB as a pack |
| POST | `/v1/pack` | upload a pack; server merges fast-forward only |

### Policy and events (untenanted)

| Method | Path | Role | Body / notes |
|---|---|---|---|
| GET | `/v1/policy` | reader | → `{ policy: PolicySet }` |
| POST | `/v1/policy` | admin | a `PolicySet` body; replaces the whole set → `{ policy }` |
| POST | `/v1/policy/evaluate` | reader | `{ head? }` → `{ generated_at, pass, warn, fail, statuses[] }` |
| GET | `/v1/events` | reader | `?since=<seq>` newer-than cursor; `?wait=<secs≤30>` long-polls → `{ events[] }` |

`enforce`-mode policies also gate `POST /v1/documents`, `/v1/runs`, and
`/v1/commits` inline — a violating write returns **403** and is recorded.
Violations append to a tamper-evident event log; see [policy.md](policy.md).

## Errors

Errors are `{ "error": "<message>", "code": "<stable>", "hint": "<how to fix>" }`
(`hint` is omitted when there is nothing actionable). Branch on `code`:

| HTTP | `code` | Cause |
|---|---|---|
| 400 | `bad_request` | malformed body or invalid value |
| 401 | `unauthorized` | missing or invalid token |
| 403 | `forbidden` | key role/tenant not permitted |
| 403 | `policy_violation` | an `enforce`-mode policy blocked the write |
| 404 | `not_found` | no such head/commit/route |
| 413 | `payload_too_large` | body over the limit |
| 503 | `overloaded` | connection cap reached |
| 5xx | `internal` | server error |

`policy_violation` is distinct from `forbidden` so a client can tell "blocked by
policy" from "insufficient role". The SDKs surface `code`/`hint` (Python raises
typed exceptions).
