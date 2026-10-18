# Retention and erasure

Erasure removes a data subject's content while keeping the hashes, manifests,
commits, and checkpoints that commit to it. You can still prove that a run or
document existed at a commit without being able to read it.

## Tagging

Content is erasable per subject only if it was tagged when written:

- runs: `subject` on `POST /v1/runs` (Python `neleus.run(subject=...)`)
- documents and chunks: `metadata.subject`

Use an opaque id. The subject id survives erasure in manifests and in the
erasure record.

## Running it

```bash
neleus-db --db ./db erasure request --subject user-123 [--reason request] [--sign-key k.key]
neleus-db --db ./db erasure list
neleus-db --db ./db erasure verify --public-key <hex>
```

HTTP: `POST /v1/erasure { subject, reason? }` (admin, untenanted) and
`GET /v1/erasure`. The record is signed when `serve` runs with `--sign-key`.

## What is removed

neleus walks the first-parent history of every head and collects:

- a run's prompt, system prompt, inputs, and outputs
- a document's original bytes and chunk blobs
- a standalone chunk's text and embedding
- the query text and embedding of any retrieval record whose hits include
  the subject's chunks

Blobs also referenced by another subject's content (through dedup) are kept.
The rest are deleted from loose files and rewritten out of packs. Without
encryption, loose files are overwritten with zeros first and the method is
`physical`; with encryption it is `crypto-shred`. If chunk content was removed,
every head's index is rebuilt so the terms and vectors are gone too.

An `ErasureRecord` (subject, blob hashes, reason, method, requester, time,
optional ed25519 signature) is appended to the event log. The next checkpoint
pins it, so a later rewrite of the log is detectable.

## What stays

- every manifest, commit, checkpoint, and retrieval record, so history and
  `seq` chains still verify
- non-content fields: subject id, model, provider, agent id, principal,
  timestamps, document `source` name, chunk metadata
- blob hashes, listed in the erasure record

Keep personal data out of these fields.

## Proofs after erasure

A blob that is missing and listed in an erasure record counts as erased. A
missing blob with no record is still an error. A chunk proof requested with
content for an erased chunk is returned with `content_erased` set and no
bytes; it still verifies the commit-to-manifest path, and a proof that sets
`content_erased` but carries bytes is rejected.

## Limits

- The subject is matched across all heads and tenants. Erasure cannot be
  scoped to one tenant, and tenant keys cannot call it.
- Session memory, state values, summary manifests, and content reachable only
  through a merge's second parent are not scanned.
- It does not check `retention_min_secs`, retention policies, or legal holds.
- It does not reach replicas, backups, packs, or proofs already exported. Erase
  on every replica; pulling from one that still has the blobs restores them.
- Scheduled retention (a per-scope TTL sweep with floors and legal holds) is
  designed but not built.
