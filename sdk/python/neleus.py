"""
neleus — Python wrapper around the neleus-db CLI for agent run capture.

Wraps every AI model call in a verifiable, content-addressed commit:

    with neleus.run(
        db="./neleus_db",
        provider="anthropic",
        model="claude-sonnet-4-6",
        agent_id="policy-reviewer-v1",
        model_parameters={"max_tokens": 1024, "temperature": 0.0},
    ) as run:
        run.system_prompt("You are a policy reviewer.")
        run.prompt("Does this policy allow email-based password reset?")
        run.retrieved_chunks(chunk_hashes)

        response = anthropic_client.messages.create(...)

        run.output(response.content[0].text)

Auto-commits on __exit__ (pass commit_message= to customise).
Use run.abort() inside the block to suppress the auto-commit.
Use run.commit(message="…") for an explicit commit and to get the manifest hash.

Requirements: neleus-db binary must be on PATH.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


class NeleusError(Exception):
    """Raised when a neleus-db CLI call fails."""


class AgentRun:
    """Records a single AI model invocation for audit and replay.

    Do not instantiate directly — use :func:`run` instead.
    """

    def __init__(
        self,
        *,
        db: str,
        provider: str,
        model: str,
        head: str = "main",
        agent_id: Optional[str] = None,
        model_parameters: Optional[dict] = None,
        sdk_version: Optional[str] = None,
        commit_message: Optional[str] = None,
        author: str = "agent",
    ) -> None:
        self._db = db
        self._provider = provider
        self._model = model
        self._head = head
        self._agent_id = agent_id
        self._model_parameters = model_parameters
        self._sdk_version = sdk_version
        self._commit_message = commit_message or f"{provider}/{model} run"
        self._author = author

        self._system_prompt: Optional[bytes] = None
        self._prompt: Optional[bytes] = None
        self._input_hashes: list[str] = []
        self._output_hashes: list[str] = []
        self._retrieved_chunk_hashes: list[str] = []
        self._tool_calls: list[dict] = []

        self._started_at: int = 0
        self._aborted: bool = False
        self._manifest_hash: Optional[str] = None

    # ------------------------------------------------------------------ #
    # context manager

    def __enter__(self) -> "AgentRun":
        self._started_at = int(time.time())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if not self._aborted and exc_type is None:
            self.commit()
        return False  # never suppress exceptions

    # ------------------------------------------------------------------ #
    # input capture

    def system_prompt(self, text: str | bytes) -> "AgentRun":
        """Set the system prompt for this run."""
        self._system_prompt = _to_bytes(text)
        return self

    def prompt(self, text: str | bytes) -> "AgentRun":
        """Set the primary user message."""
        self._prompt = _to_bytes(text)
        return self

    def input(self, content: str | bytes) -> "AgentRun":
        """Store an additional input blob and track its hash.

        Blobs are written to the DB immediately so partial runs are recoverable.
        """
        blob_hash = self._store_blob_inline(content)
        self._input_hashes.append(blob_hash)
        return self

    def output(self, content: str | bytes) -> "AgentRun":
        """Store an output blob and track its hash."""
        blob_hash = self._store_blob_inline(content)
        self._output_hashes.append(blob_hash)
        return self

    def retrieved_chunks(self, chunk_hashes: list[str]) -> "AgentRun":
        """Link retrieved knowledge-base chunk hashes to this run.

        Closes the RAG audit loop: query → chunks → prompt → output → commit.
        """
        self._retrieved_chunk_hashes.extend(chunk_hashes)
        return self

    def tool_call(
        self,
        tool: str,
        *,
        input_hash: Optional[str] = None,
        output_hash: Optional[str] = None,
    ) -> "AgentRun":
        """Record a tool invocation by its input/output blob hashes."""
        self._tool_calls.append({"tool": tool, "in": input_hash, "out": output_hash})
        return self

    # ------------------------------------------------------------------ #
    # commit / abort

    def abort(self) -> None:
        """Suppress the auto-commit that would fire on __exit__."""
        self._aborted = True

    def commit(self, *, message: Optional[str] = None) -> str:
        """Persist the run manifest and create a DB commit.

        Returns the manifest hash. Safe to call more than once (each call
        creates a new manifest + commit against the current DB state).
        """
        ended_at = int(time.time())
        msg = message or self._commit_message

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            args = self._build_put_run_args(tmp_path, ended_at)

        result = self._cli(args)
        self._manifest_hash = result["manifest_hash"]

        self._cli([
            "commit", "new",
            "--head", self._head,
            "--author", self._author,
            "--message", msg,
            "--manifest", self._manifest_hash,
        ])

        return self._manifest_hash

    @property
    def manifest_hash(self) -> Optional[str]:
        """The hash of the most recently committed RunManifest, or None."""
        return self._manifest_hash

    # ------------------------------------------------------------------ #
    # internals

    def _build_put_run_args(self, tmp: Path, ended_at: int) -> list[str]:
        """Assemble the `manifest put-run` CLI argument list, writing temp files as needed."""
        prompt_bytes = self._prompt or b""
        prompt_file = tmp / "prompt.bin"
        prompt_file.write_bytes(prompt_bytes)

        args = [
            "manifest", "put-run",
            "--model", self._model,
            "--prompt-file", str(prompt_file),
            "--started-at", str(self._started_at or ended_at),
            "--ended-at", str(ended_at),
        ]

        if self._provider:
            args += ["--provider", self._provider]
        if self._agent_id:
            args += ["--agent-id", self._agent_id]
        if self._sdk_version:
            args += ["--sdk-version", self._sdk_version]

        if self._system_prompt is not None:
            sp_file = tmp / "system_prompt.bin"
            sp_file.write_bytes(self._system_prompt)
            args += ["--system-prompt-file", str(sp_file)]

        if self._model_parameters:
            # Sort keys so identical parameter sets always hash identically.
            params_file = tmp / "params.json"
            params_file.write_text(
                json.dumps(self._model_parameters, sort_keys=True), encoding="utf-8"
            )
            args += ["--params-json", str(params_file)]

        for h in self._input_hashes:
            args += ["--io-hashes", f"in:{h}"]
        for h in self._output_hashes:
            args += ["--io-hashes", f"out:{h}"]
        for h in self._retrieved_chunk_hashes:
            args += ["--retrieved-chunk", h]

        return args

    def _store_blob_inline(self, content: str | bytes) -> str:
        """Store a blob immediately and return its hash."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(_to_bytes(content))
            f.flush()
            result = self._cli(["blob", "put", f.name])
        return result["hash"]

    def _cli(self, args: list[str]) -> dict:
        """Run a neleus-db command and return parsed JSON output.

        Raises :exc:`NeleusError` on non-zero exit.
        """
        cmd = ["neleus-db", "--db", self._db, "--json"] + args
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
            return json.loads(out) if out.strip() else {}
        except subprocess.CalledProcessError as e:
            raise NeleusError(
                f"neleus-db command failed (exit {e.returncode}):\n"
                f"  cmd:    {' '.join(cmd)}\n"
                f"  stderr: {e.stderr.strip()}"
            ) from e
        except FileNotFoundError as e:
            raise NeleusError(
                "neleus-db binary not found on PATH. "
                "Build with `cargo build --release` and add the binary to your PATH."
            ) from e


def run(
    *,
    db: str,
    provider: str,
    model: str,
    head: str = "main",
    agent_id: Optional[str] = None,
    model_parameters: Optional[dict] = None,
    sdk_version: Optional[str] = None,
    commit_message: Optional[str] = None,
    author: str = "agent",
) -> AgentRun:
    """Create an :class:`AgentRun` context manager for a single model invocation.

    Args:
        db: path to the neleus-db data directory.
        provider: AI provider name, e.g. ``"anthropic"`` or ``"openai"``.
        model: model identifier, e.g. ``"claude-sonnet-4-6"``.
        head: DB branch name (default ``"main"``).
        agent_id: logical agent name or version, e.g. ``"policy-reviewer-v1"``.
        model_parameters: dict of sampling parameters, e.g.
            ``{"max_tokens": 1024, "temperature": 0.0}``. Stored as a
            content-addressed blob so identical configs deduplicate across runs.
        sdk_version: caller SDK version string, e.g. ``"anthropic-python/0.40.0"``.
        commit_message: override the auto-generated commit message.
        author: commit author name (default ``"agent"``).

    Example::

        with neleus.run(
            db="./neleus_db",
            provider="anthropic",
            model="claude-sonnet-4-6",
            agent_id="code-reviewer-v1",
            model_parameters={"max_tokens": 1024, "temperature": 0.2},
        ) as run:
            run.system_prompt("You are a code reviewer.")
            run.prompt(user_message)
            run.retrieved_chunks(chunk_hashes)

            response = anthropic_client.messages.create(...)

            run.output(response.content[0].text)
        # auto-committed here — every input, output, and retrieved chunk
        # is now content-addressed and provably linked.
    """
    return AgentRun(
        db=db,
        provider=provider,
        model=model,
        head=head,
        agent_id=agent_id,
        model_parameters=model_parameters,
        sdk_version=sdk_version,
        commit_message=commit_message,
        author=author,
    )


def _to_bytes(value: str | bytes) -> bytes:
    return value.encode() if isinstance(value, str) else value
