# CLI reference

Two binaries: `neleus-db` (database + server) and `neleus-verify` (standalone
audit verifier).

Global flags on `neleus-db`:

- `--db <path>` — database directory (default `./neleus_db`).
- `--json` — machine-readable output. Most commands honor it.

Run `neleus-db <group> --help` for the authoritative flag list; this is the
map.

## db — lifecycle, backup, GC, replication

| Command | What it does |
|---|---|
| `db init <path>` | Create a new database. |
| `db reencrypt --new-password-env <VAR>` | Rotate the encryption password (re-wraps ciphertext; `master_salt` unchanged). |
| `db pack <out> [--compress]` | Export the whole DB to one self-contained file. |
| `db unpack <input> [--force] [--verify-only]` | Restore from a pack; `--verify-only` checks integrity without writing. |
| `db repack` | Consolidate loose objects into pack files. |
| `db packs` | List internal pack files. |
| `db gc [--prune] [--grace-secs <n>]` | Reclaim unreachable objects. Dry-run unless `--prune`. |
| `db pull --remote <url> [--token-env <VAR>]` | Pull missing objects + fast-forward refs from a `serve` peer. |
| `db push --remote <url> [--token-env <VAR>]` | Push to a `serve` peer (fast-forward only). |

## blob / object — raw content

| Command | What it does |
|---|---|
| `blob put <file>` | Store bytes, print the hash. |
| `blob get <hash> <out>` | Read bytes by hash. |
| `object inspect <hash>` | Decode an object, reporting its detected type. |

## manifest — documents and runs

| Command | What it does |
|---|---|
| `manifest put-doc --source <s> --file <f> --chunk-size <n> [--overlap <n>] [--doc-type <t>] [--language <l>] [--valid-from <unix>] [--valid-to <unix>] [--expires-at <unix>] [--acl <tag>]…` | Chunk a file, store chunks + a `DocManifest` with metadata. |
| `manifest put-run --model <m> --prompt-file <f> [--provider …] [--system-prompt-file …] [--params-json …] [--param k=v]… [--retrieved-chunk <hash>]… [--io-hashes in:<hash>] [--io-hashes out:<hash>] …` | Record one model invocation as a `RunManifest`. |

## state — versioned KV

| Command | What it does |
|---|---|
| `state set <head> <key> <value-file> [--key-encoding utf8\|hex\|base64]` | Write a value. |
| `state get <head> <key> [--key-encoding …] [--out-file <p>]` | Read a value. |
| `state del <head> <key> [--key-encoding …]` | Delete a key. |
| `state set-many <head> <entries-file>` / `state del-many <head> <keys-file>` | Batch writes/deletes from a JSON file. |
| `state compact <head>` | No-op — the prolly-tree state is always canonical (retained for compatibility). |

## commit / log / proof — history and proofs

| Command | What it does |
|---|---|
| `commit new --head <h> --author <a> --message <m> [--manifest <hash>]… [--sign-key <key>]` | Create a commit, optionally ed25519-signed; auto-indexes. |
| `commit verify <hash> --public-key <hex>` | Verify a signed commit. |
| `log <head>` | Walk commit history. |
| `proof state <head> <key> [--key-encoding …]` | Membership/non-membership proof for a key. |
| `proof chunk --head <h> --chunk <hash> [--include-content] [--out <file>]` | Build an offline chunk-proof bundle. |
| `proof verify-chunk <input>` | Verify a chunk-proof bundle (exit 1 on invalid). |

## index / search — retrieval

| Command | What it does |
|---|---|
| `index build --head <h>` | Build the index for a commit (also happens lazily on first query). |
| `index stats --head <h>` | Segment/chunk/term/vector counts. |
| `search semantic --head <h> (--query <q> \| --query-file <f>) [--top-k <n>] [filters] [--audit]` | BM25 search. |
| `search vector --head <h> --embedding-file <f> [--top-k <n>] [filters] [--audit]` | HNSW vector search. |
| `search hybrid --head <h> [--query <q>] [--embedding-file <f>] [--top-k <n>] [filters] [--audit]` | BM25 + vector, RRF-fused. |

`head` accepts a branch name or a 64-hex commit hash (time-travel). Filter
flags shared by all modes: `--tenant`, `--doc-type`, `--language`, `--acl
<tag>` (repeatable), `--valid-at <unix>`. `--audit` records a `QueryManifest`
and prints its hash; attach it with `commit new --manifest <hash>` to make it
durable.

## key / checkpoint — signing and transparency log

| Command | What it does |
|---|---|
| `key generate --out <file>` | Generate an ed25519 keypair; prints the public key, writes the seed (0600). |
| `checkpoint new --head <h> [--sign-key <key>]` | Append a checkpoint to the head's chain. |
| `checkpoint verify --head <h> [--public-key <hex>] [--require-signatures]` | Verify the chain to genesis. |

## session — episodic memory

| Command | What it does |
|---|---|
| `session append --head <h> --session-id <id> [--role <r>] (--content <s> \| --content-file <f>) [--ttl-secs <n>]` | Append a turn. |
| `session list --head <h> --session-id <id> [--include-expired]` | List turns (oldest first). |
| `session gc --head <h>` | Remove expired records (honors the retention floor). |

## audit / compliance — the compliance surface

| Command | What it does |
|---|---|
| `audit log --head <h> [--from <unix>] [--to <unix>]` | List retrieval audit records. |
| `audit export --head <h> [--from] [--to] --out <file> [--sign-key <key>]` | Write a self-contained, optionally signed bundle. |
| `audit verify <input> [--public-key <hex>] [--require-signature]` | Verify a bundle offline (same as `neleus-verify`). |
| `audit report --head <h> --framework <id> [--from] [--to] [--out <file>]` | Markdown compliance report with live checks. |
| `compliance frameworks` | The law catalog, grouped by jurisdiction. |
| `compliance status --head <h> [--from] [--to]` | Per-law overall status: satisfied / in-review / gap. |
| `compliance check --head <h> --framework <id> [--from] [--to]` | Full check list for one framework. |

## policy / events — monitor and enforce

| Command | What it does |
|---|---|
| `policy list` | Print the current policy set. |
| `policy set <file.json>` | Replace the whole set (policy-as-code apply). |
| `policy rm --id <id>` | Remove one policy. |
| `policy eval [--head <h>]` | Score every enabled policy against live state. |
| `events list [--since <seq>]` | List recorded violation/enforcement events. |
| `events verify` | Verify the event chain is intact (tamper-evident). |

`enforce`-mode policies also gate the server's write endpoints. See
[policy.md](policy.md).

## serve / auth — hosted mode

| Command | What it does |
|---|---|
| `serve --addr <a> [--open] [--no-bootstrap] [--allow-remote] [--no-auth] [--cors-origin <origin>]` | Start the HTTP server + bundled console. |
| `auth add-key --id <id> --role <reader\|writer\|admin> [--tenant <t>]` | Mint an API token (printed once). |
| `auth remove-key --id <id>` | Revoke a key. |
| `auth list-keys` | List key metadata (never secrets). |

`serve` bundles the web console at `/` and prints a `neleus://…` connection
string on startup. `--open` launches a browser; on loopback a bootstrap admin
token is minted (disable with `--no-bootstrap`). See [http-api.md](http-api.md)
for the routes.

## neleus-verify — standalone auditor binary

No database, no network. Hand it the bundle.

```
neleus-verify <bundle.nelaudit> [--public-key <hex>] [--require-signature] [--json]
```

Prints `VERIFIED: …` and exits 0, or `INVALID: …` and exits 1. Every claim is
re-derived from bytes carried in the bundle.
