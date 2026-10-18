# CLI reference

Two binaries: `neleus-db` and `neleus-verify`. Global flags: `--db <path>`
(default `./neleus_db`), `--json`. `neleus-db <group> <cmd> --help` is
authoritative.

## db

- `db init <path> [--replica-of <url>] [--token-env <VAR>]`: Create a database; `--replica-of` clones a `serve` peer and adopts its secret.
- `db reencrypt [--new-password-env <VAR>]`: Rotate the encryption password (default env `NELEUS_DB_NEW_ENCRYPTION_PASSWORD`).
- `db pack <out> [--compress]`: Export to one file; `--compress` uses zstd.
- `db unpack <input> [--force] [--verify-only]`: Restore from a pack, or only check it.
- `db repack`: Consolidate loose objects into packs.
- `db packs`: List pack files.
- `db gc [--prune] [--grace-secs <n>]`: Report unreachable objects; delete with `--prune`. Grace default 3600.
- `db pull --remote <url> [--token-env <VAR>]`: Pull objects and fast-forward refs from a peer.
- `db push --remote <url> [--token-env <VAR>]`: Push to a peer (fast-forward only).

`--token-env` defaults to `NELEUS_DB_TOKEN`; the remote needs an admin key.

## blob, object

- `blob put <file>`: Store bytes, print the hash.
- `blob get <hash> <out-file>`: Write bytes for a hash.
- `object inspect <hash>`: Decode an object and report its type.

## manifest

- `manifest put-doc --source <s> --file <f> --chunk-size <n>`: Chunk a file and store a `DocManifest`.
- `manifest put-run --model <m> --prompt-file <f>`: Record one model call as a `RunManifest`.

`put-doc` flags: `--overlap <n>` (default 0), `--tenant <t>`, `--doc-type <t>`,
`--language <l>`, `--valid-from <unix>`, `--valid-to <unix>`,
`--expires-at <unix>`, `--acl <tag>` (repeatable).

`put-run` flags: `--provider <p>`, `--system-prompt-file <f>`,
`--params-json <f>`, `--param k=v` (repeatable, numbers and bools inferred),
`--retrieved-chunk <hash>` (repeatable), `--io-hashes in:<hash>|out:<hash>`
(repeatable), `--sdk-version <v>`, `--agent-id <id>`, `--started-at <unix>`,
`--ended-at <unix>` (both default to now).

## state

- `state set <head> <key> <value-file>`: Write a value.
- `state get <head> <key> [--out-file <p>]`: Read a value.
- `state del <head> <key>`: Delete a key.
- `state set-many <head> <entries-file>`: Batch write; JSON `[{"key": "...", "value_base64": "..."}]`.
- `state del-many <head> <keys-file>`: Batch delete; JSON `["k1", "k2"]`.
- `state compact <head>`: No-op; the tree is always canonical. Prints the state root.

`set`, `get`, `del` take `--key-encoding utf8|hex|base64` (default `utf8`).

## commit, log, proof

- `commit new --head <h> --author <a> --message <m> [--manifest <hash>]... [--sign-key <seed>]`: Create a commit, optionally ed25519-signed.
- `commit verify <hash> --public-key <hex>`: Verify a signed commit.
- `log <head>`: Walk commit history.
- `proof state <head> <key> [--key-encoding ...]`: Membership or non-membership proof.
- `proof chunk --head <h> --chunk <hash> [--include-content] [--anchor-head <h>] [--out <file>]`: Chunk proof bundle. `--head` is a head or commit; `--anchor-head` adds inclusion in that head's latest checkpoint; without `--out`, prints base64 JSON.
- `proof verify-chunk <input>`: Verify a CBOR bundle from `proof chunk --out`; exit 1 if invalid.

## index, search

- `index build --head <h>`: Build the index (also built lazily on first query).
- `index stats --head <h>`: Segment, chunk, term, and vector counts.
- `search semantic --head <h> (--query <q> | --query-file <f>)`: BM25.
- `search vector --head <h> --embedding-file <f>`: HNSW vector search.
- `search hybrid --head <h> [--query <q> | --query-file <f>] [--embedding-file <f>]`: BM25 + vector, RRF-fused.

Search flags: `--at <commit>` (search a past commit), `--top-k <n>` (default
10), `--tenant <t>`, `--doc-type <t>`, `--language <l>`, `--acl <tag>`
(repeatable), `--valid-at <unix>`.

Every search is recorded on `--head`, including `--at` searches. The record
hash is printed.

## key, checkpoint

- `key generate --out <file>`: Write an ed25519 seed (0600), print the public key.
- `checkpoint new --head <h> [--sign-key <seed>]`: Append a checkpoint.
- `checkpoint verify --head <h> [--public-key <hex>] [--require-signatures]`: Verify the chain to genesis.

## session

- `session append --head <h> --session-id <id> [--role <r>] (--content <s> | --content-file <f>) [--ttl-secs <n>]`: Append a turn. Roles: `user`, `assistant`, `tool`, `summary`, ...
- `session list --head <h> --session-id <id> [--include-expired]`: List turns, oldest first.
- `session gc --head <h>`: Remove expired records.

## audit

- `audit log --head <h> [--from <unix>] [--to <unix>]`: List retrieval records.
- `audit export --head <h> --out <file> [--from] [--to] [--sign-key <seed>] [--anchor <checkpoint>]`: Write a `.nelaudit` bundle; `--anchor` adds a consistency proof from a retained checkpoint.
- `audit verify <input> [--public-key <hex>] [--require-signature] [--anchor <checkpoint>]`: Verify a bundle offline, same as `neleus-verify`.

`--from`/`--to` default to the full history.

## policy, events

- `policy list`: Print the policy set.
- `policy set <file>`: Replace the set from JSON `{"policies":[{"id","rule","mode"}]}`.
- `policy rm --id <id>`: Remove one policy.
- `policy eval [--head <h>]`: Evaluate enabled policies against live state.
- `events list [--since <seq>]`: List violation and enforcement events.
- `events verify`: Verify the event hash chain.

`enforce` policies also gate server writes. See [policy.md](policy.md).

## erasure

- `erasure request --subject <id> [--reason request|ttl|account-closure] [--sign-key <seed>]`: Shred the subject's content; commit hashes stay intact.
- `erasure list`: List erasure records.
- `erasure verify --public-key <hex>`: Check signed erasure records.

With encryption at rest this is a crypto-shred; without it, overwrite is
best-effort on copy-on-write filesystems and SSDs.

## serve, auth

- `serve`: Start the HTTP server and bundled console.
- `auth add-key --id <id> --role reader|writer|admin [--tenant <t>]`: Mint an API token (printed once); `--tenant` pins it to `<tenant>/`.
- `auth remove-key --id <id>`: Revoke a key.
- `auth list-keys`: List key metadata.

`serve` flags:

- `--addr <a>`: Bind address (default `127.0.0.1:7117`).
- `--allow-remote`: Allow non-loopback binds; requires auth keys. Terminate TLS in front.
- `--no-auth`: Disable auth (loopback only).
- `--no-bootstrap`: Do not mint the loopback bootstrap admin token.
- `--cors-origin <origin>`: Set `Access-Control-Allow-Origin`; `*` allows any.
- `--open`: Open the console in a browser.
- `--sign-key <seed>`: Sign audit bundles exported over HTTP.

Routes: [http-api.md](http-api.md).

## neleus-verify

```
neleus-verify <bundle> [--public-key <hex>] [--require-signature] [--anchor <checkpoint>] [--json]
```

Needs no database or network. Prints `VERIFIED: ...` and exits 0, or
`INVALID: ...` and exits 1. The report includes `commits_signed` and
`commit_keys` (keys that signed carried commits); compare those with the keys
you trust.
