"""
Example: audit a Claude model call end-to-end.

Shows the full flow:
  document chunks → retrieval → Claude call → provenance claim → commit → proof

Prerequisites
-------------
1. Build and install the CLI:
       cargo build --release
       export PATH="$PWD/target/release:$PATH"

2. Install the Anthropic SDK:
       pip install anthropic

3. Set your API key:
       export ANTHROPIC_API_KEY="sk-ant-..."

4. Add sdk/python to your path:
       export PYTHONPATH="$PWD/sdk/python:$PYTHONPATH"
"""

import json
import subprocess
import sys
from pathlib import Path

try:
    import anthropic
except ImportError:
    sys.exit("Install the anthropic package: pip install anthropic")

import neleus

DB = "./neleus_demo"
HEAD = "main"

POLICY_TEXT = """\
Password Reset Policy
---------------------
Users may reset their password by:
1. Providing their registered email address.
2. Clicking the one-time link sent to that address within 30 minutes.
3. Entering a new password that meets the complexity requirements.

Phone-based reset requires speaking with a support agent during business hours.
"""

QUESTION = "Does this policy allow users to reset their password using email?"


def init_db() -> None:
    subprocess.run(
        ["neleus-db", "--db", DB, "--json", "db", "init", DB],
        check=True,
        capture_output=True,
    )


def ingest_document() -> list[str]:
    """Chunk the policy document and return the chunk hashes."""
    policy_file = Path("/tmp/policy.txt")
    policy_file.write_text(POLICY_TEXT)

    result = subprocess.check_output(
        [
            "neleus-db", "--db", DB, "--json",
            "manifest", "put-doc",
            "--source", "policy.txt",
            "--file", str(policy_file),
            "--chunk-size", "256",
            "--overlap", "32",
        ],
        text=True,
    )
    manifest_hash = json.loads(result)["manifest_hash"]

    # Build the search index so we can retrieve chunks.
    subprocess.run(
        [
            "neleus-db", "--db", DB,
            "commit", "new",
            "--head", HEAD,
            "--author", "ingestion",
            "--message", "ingest policy document",
            "--manifest", manifest_hash,
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["neleus-db", "--db", DB, "index", "build", "--head", HEAD],
        check=True,
        capture_output=True,
    )

    hits = json.loads(
        subprocess.check_output(
            [
                "neleus-db", "--db", DB, "--json",
                "search", "semantic",
                "--head", HEAD,
                "--query", QUESTION,
                "--top-k", "3",
            ],
            text=True,
        )
    )
    return [h["chunk_hash"] for h in hits.get("hits", [])]


def main() -> None:
    print("Initialising DB …")
    init_db()

    print("Ingesting policy document …")
    chunk_hashes = ingest_document()
    print(f"  retrieved {len(chunk_hashes)} chunks")

    client = anthropic.Anthropic()

    print("Running Claude with full audit trail …")
    with neleus.run(
        db=DB,
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        agent_id="policy-reviewer-v1",
        model_parameters={"max_tokens": 512, "temperature": 0.0},
        commit_message="policy Q&A run",
    ) as run:
        system = "You are a policy analyst. Answer concisely and cite the policy text."
        run.system_prompt(system)
        run.prompt(QUESTION)
        run.retrieved_chunks(chunk_hashes)

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": QUESTION}],
        )
        answer = response.content[0].text
        run.output(answer)

    manifest_hash = run.manifest_hash
    print(f"\nAnswer: {answer}\n")
    print(f"Manifest hash: {manifest_hash}")

    # Generate a state proof for the DB head to demonstrate tamper-evidence.
    proof = json.loads(
        subprocess.check_output(
            [
                "neleus-db", "--db", DB, "--json",
                "proof", "state", HEAD, "seed",
                "--key-encoding", "utf8",
            ],
            text=True,
        )
    )
    print(f"State root:    {proof['root_hash']}")
    print(f"Proof verified: {proof['verified']}")
    print("\nEvery input, retrieved chunk, and output is content-addressed and linked.")
    print("Re-run `neleus-db log main` to inspect the full commit history.")


if __name__ == "__main__":
    main()
