"""
neleus — Python client for neleus-db agent run capture and retrieval.

Two transports, same API:

- HTTP (preferred): point at a `neleus-db serve` instance. One persistent
  process, microsecond-warm queries, no per-call process spawn.
- CLI (fallback): shells out to the neleus-db binary per call. Works with
  zero infrastructure, but pays process-spawn latency on every operation.

Run capture:

    with neleus.run(
        url="neleus://nlk_...@127.0.0.1:7117",
        provider="anthropic", model="claude-sonnet-4-6",
        agent_id="policy-reviewer-v1",
        model_parameters={"max_tokens": 1024, "temperature": 0.0},
    ) as run:
        run.system_prompt("You are a policy reviewer.")
        run.prompt(user_question)
        run.retrieved_chunks(chunk_hashes)
        response = anthropic_client.messages.create(...)
        run.output(response.content[0].text)
    # auto-commits: inputs, outputs, and retrieved chunks are now
    # content-addressed and provably linked.

Retrieval (HTTP only):

    client = neleus.connect("neleus://nlk_...@127.0.0.1:7117")
    hits = client.search("main", query="reset policy", top_k=5, audit=True)
    proof = client.prove(hits["commit"], hits["hits"][0]["chunk"])
    assert client.verify(proof)["valid"]
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

DEFAULT_PORT = 7117


class NeleusError(Exception):
    """A neleus-db call failed. Carries the server's `code`, `hint`, `status`."""

    def __init__(self, message: str, *, code: Optional[str] = None,
                 hint: Optional[str] = None, status: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.hint = hint
        self.status = status


class PolicyViolation(NeleusError): ...  # code=policy_violation
class Unauthorized(NeleusError): ...     # code=unauthorized
class Forbidden(NeleusError): ...        # code=forbidden
class NotFound(NeleusError): ...         # code=not_found
class BadRequest(NeleusError): ...       # code=bad_request


_CODE_EXC = {
    "policy_violation": PolicyViolation,
    "unauthorized": Unauthorized,
    "forbidden": Forbidden,
    "not_found": NotFound,
    "bad_request": BadRequest,
}


def _raise_http(status: int, path: str, detail: str) -> None:
    """Parse the `{error, code, hint}` envelope and raise the typed exception."""
    code = hint = None
    msg = detail
    try:
        body = json.loads(detail)
        msg = body.get("error", detail)
        code = body.get("code")
        hint = body.get("hint")
    except Exception:
        pass
    text = f"{path} -> HTTP {status}: {msg}" + (f"\n  fix: {hint}" if hint else "")
    raise _CODE_EXC.get(code, NeleusError)(text, code=code, hint=hint, status=status)


def _parse_conn_str(conn: str) -> tuple[str, Optional[str]]:
    """neleus://[<token>@]<host>[:<port>] -> (base_url, token). `neleuss://` = TLS."""
    if conn.startswith("neleuss://"):
        proto, rest = "https", conn[len("neleuss://"):]
    elif conn.startswith("neleus://"):
        proto, rest = "http", conn[len("neleus://"):]
    else:
        raise NeleusError(
            f"not a neleus connection string: {conn!r} (expected neleus://[token@]host[:port])"
        )
    rest = rest.rstrip("/")
    token: Optional[str] = None
    if "@" in rest:
        token, rest = rest.split("@", 1)
        token = token or None
    if ":" not in rest:
        rest = f"{rest}:{DEFAULT_PORT}"
    return f"{proto}://{rest}", token


def connect(conn_str: Optional[str] = None, *, token: Optional[str] = None) -> "Client":
    # conn_str: a neleus:// string, an http(s):// base URL, or None -> $NELEUS_URL.
    conn_str = conn_str or os.environ.get("NELEUS_URL")
    if not conn_str:
        url = f"http://127.0.0.1:{DEFAULT_PORT}"
    elif conn_str.startswith(("neleus://", "neleuss://")):
        url, parsed = _parse_conn_str(conn_str)
        token = token or parsed
    else:
        url = conn_str
    return Client(url, token=token)


# --------------------------------------------------------------------------- #
# transports


class HttpTransport:
    """Talks to `neleus-db serve` over HTTP/1.1 (stdlib only)."""

    def __init__(self, url: str, token: Optional[str] = None, timeout: float = 600.0):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method,
            headers={"content-type": "application/json"},
        )
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            _raise_http(e.code, path, e.read().decode(errors="replace"))
        except urllib.error.URLError as e:
            raise NeleusError(f"cannot reach neleus-db at {self.url}: {e.reason}") from e

    def blob_put(self, content: bytes) -> str:
        req = urllib.request.Request(
            self.url + "/v1/blobs", data=content, method="POST",
            headers={"content-type": "application/octet-stream"},
        )
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())["hash"]
        except urllib.error.HTTPError as e:
            _raise_http(e.code, "/v1/blobs", e.read().decode(errors="replace"))

    def put_run(self, fields: dict) -> tuple[str, Optional[str]]:
        out = self.request("POST", "/v1/runs", fields)
        return out["manifest"], out.get("commit")


class CliTransport:
    """Shells out to the neleus-db binary; pays process spawn per call."""

    def __init__(self, db: str):
        self.db = db

    def cli(self, args: list[str]) -> dict:
        cmd = ["neleus-db", "--db", self.db, "--json"] + args
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
            return json.loads(out) if out.strip() else {}
        except subprocess.CalledProcessError as e:
            raise NeleusError(
                f"neleus-db failed (exit {e.returncode}): {e.stderr.strip()}"
            ) from e
        except FileNotFoundError as e:
            raise NeleusError(
                "neleus-db binary not found on PATH; build with `cargo build --release`"
            ) from e

    def blob_put(self, content: bytes) -> str:
        with tempfile.NamedTemporaryFile() as f:
            f.write(content)
            f.flush()
            return self.cli(["blob", "put", f.name])["hash"]

    def put_run(self, fields: dict) -> tuple[str, Optional[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.bin"
            prompt_file.write_bytes(fields.get("prompt", "").encode())
            args = [
                "manifest", "put-run",
                "--model", fields["model"],
                "--prompt-file", str(prompt_file),
                "--started-at", str(fields["started_at"]),
                "--ended-at", str(fields["ended_at"]),
            ]
            if fields.get("provider"):
                args += ["--provider", fields["provider"]]
            if fields.get("agent_id"):
                args += ["--agent-id", fields["agent_id"]]
            if fields.get("sdk_version"):
                args += ["--sdk-version", fields["sdk_version"]]
            if fields.get("system_prompt") is not None:
                sp = tmp_path / "system_prompt.bin"
                sp.write_bytes(fields["system_prompt"].encode())
                args += ["--system-prompt-file", str(sp)]
            if fields.get("model_parameters"):
                params = tmp_path / "params.json"
                params.write_text(
                    json.dumps(fields["model_parameters"], sort_keys=True)
                )
                args += ["--params-json", str(params)]
            for h in fields.get("inputs", []):
                args += ["--io-hashes", f"in:{h}"]
            for h in fields.get("outputs", []):
                args += ["--io-hashes", f"out:{h}"]
            for h in fields.get("retrieved_chunks", []):
                args += ["--retrieved-chunk", h]
            manifest = self.cli(args)["manifest_hash"]

        if fields.get("commit", True):
            commit = self.cli([
                "commit", "new",
                "--head", fields["head"],
                "--author", fields.get("author", "agent"),
                "--message", fields.get("message", "agent run"),
                "--manifest", manifest,
            ])["commit_hash"]
        else:
            commit = None
        return manifest, commit


# --------------------------------------------------------------------------- #
# retrieval client (HTTP)


class Client:
    """Search, sessions, and proofs against a `neleus-db serve` instance."""

    def __init__(self, url: str, token: Optional[str] = None):
        self._t = HttpTransport(url, token)

    def put_document(
        self, head: str, source: str, text: str, *,
        chunk_size: int = 512, overlap: int = 64, metadata: Optional[dict] = None,
    ) -> dict:
        return self._t.request("POST", "/v1/documents", {
            "head": head, "source": source, "text": text,
            "chunk_size": chunk_size, "overlap": overlap, "metadata": metadata,
        })

    def search(
        self, at: str, *, query: Optional[str] = None,
        embedding: Optional[list[float]] = None, mode: str = "hybrid",
        top_k: int = 10, filter: Optional[dict] = None, audit: bool = False,
    ) -> dict:
        return self._t.request("POST", "/v1/search", {
            "at": at, "mode": mode, "query": query, "embedding": embedding,
            "top_k": top_k, "filter": filter, "audit": audit,
        })

    def prove(self, commit: str, chunk: str, *, include_content: bool = True) -> str:
        out = self._t.request("POST", "/v1/proofs/chunk", {
            "commit": commit, "chunk": chunk, "include_content": include_content,
        })
        return out["proof_cbor"]

    def verify(self, proof_cbor: str) -> dict:
        return self._t.request("POST", "/v1/proofs/verify", {"proof_cbor": proof_cbor})

    def session_append(
        self, head: str, session_id: str, content: str, *,
        role: Optional[str] = None, ttl_secs: Optional[int] = None,
    ) -> dict:
        return self._t.request("POST", "/v1/sessions/append", {
            "head": head, "session_id": session_id, "content": content,
            "role": role, "ttl_secs": ttl_secs,
        })

    def session_list(self, head: str, session_id: str) -> list[dict]:
        out = self._t.request("POST", "/v1/sessions/list", {
            "head": head, "session_id": session_id,
        })
        return out["turns"]

    def state_get(self, head: str, key: bytes) -> Optional[bytes]:
        import base64
        out = self._t.request("POST", "/v1/state/get", {
            "head": head, "key": base64.b64encode(key).decode(),
        })
        return base64.b64decode(out["value"]) if out.get("value") else None

    def state_set(self, head: str, key: bytes, value: bytes) -> str:
        import base64
        out = self._t.request("POST", "/v1/state/set", {
            "head": head,
            "key": base64.b64encode(key).decode(),
            "value": base64.b64encode(value).decode(),
        })
        return out["root"]

    def checkpoint(self, head: str) -> str:
        return self._t.request("POST", "/v1/checkpoints", {"head": head})["checkpoint"]

    def health(self) -> dict:
        return self._t.request("GET", "/v1/health")


# --------------------------------------------------------------------------- #
# run capture


class AgentRun:
    """Records one model invocation for audit and replay. Use :func:`run`."""

    def __init__(self, *, transport: Any, head: str, provider: str, model: str,
                 agent_id: Optional[str], model_parameters: Optional[dict],
                 sdk_version: Optional[str], commit_message: Optional[str],
                 author: str, trace_id: Optional[str] = None,
                 parent_span: Optional[str] = None,
                 delegated_from: Optional[str] = None,
                 subject: Optional[str] = None) -> None:
        self._t = transport
        self._head = head
        self._provider = provider
        self._model = model
        self._agent_id = agent_id
        self._model_parameters = model_parameters
        self._sdk_version = sdk_version
        self._commit_message = commit_message or f"{provider}/{model} run"
        self._author = author
        # trace_id groups runs across agent handoffs and model switches;
        # parent_span is the parent run's manifest hash (a verifiable span edge).
        self._trace_id = trace_id
        self._parent_span = parent_span
        self._delegated_from = delegated_from
        self._subject = subject

        self._system_prompt: Optional[str] = None
        self._prompt: Optional[str] = None
        self._input_hashes: list[str] = []
        self._output_hashes: list[str] = []
        self._retrieved_chunk_hashes: list[str] = []
        self._started_at: int = 0
        self._aborted = False
        self._manifest_hash: Optional[str] = None
        self._commit_hash: Optional[str] = None

    def __enter__(self) -> "AgentRun":
        self._started_at = int(time.time())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if not self._aborted and exc_type is None:
            self.commit()
        return False

    def system_prompt(self, text: str | bytes) -> "AgentRun":
        self._system_prompt = _to_str(text)
        return self

    def prompt(self, text: str | bytes) -> "AgentRun":
        self._prompt = _to_str(text)
        return self

    def input(self, content: str | bytes) -> "AgentRun":
        """Store an input blob immediately; partial runs stay recoverable."""
        self._input_hashes.append(self._t.blob_put(_to_bytes(content)))
        return self

    def output(self, content: str | bytes) -> "AgentRun":
        self._output_hashes.append(self._t.blob_put(_to_bytes(content)))
        return self

    def retrieved_chunks(self, chunk_hashes: list[str]) -> "AgentRun":
        """Link retrieved chunk hashes: closes the RAG audit loop."""
        self._retrieved_chunk_hashes.extend(chunk_hashes)
        return self

    def abort(self) -> None:
        """Suppress the auto-commit on __exit__."""
        self._aborted = True

    def commit(self, *, message: Optional[str] = None) -> str:
        """Persist the RunManifest + commit. Returns the manifest hash."""
        manifest, commit = self._t.put_run({
            "head": self._head,
            "model": self._model,
            "provider": self._provider,
            "prompt": self._prompt or "",
            "system_prompt": self._system_prompt,
            "model_parameters": self._model_parameters,
            "inputs": self._input_hashes,
            "outputs": self._output_hashes,
            "retrieved_chunks": self._retrieved_chunk_hashes,
            "agent_id": self._agent_id,
            "trace_id": self._trace_id,
            "parent_span": self._parent_span,
            "delegated_from": self._delegated_from,
            "subject": self._subject,
            "sdk_version": self._sdk_version,
            "started_at": self._started_at or int(time.time()),
            "ended_at": int(time.time()),
            "message": message or self._commit_message,
            "author": self._author,
            "commit": True,
        })
        self._manifest_hash = manifest
        self._commit_hash = commit
        return manifest

    @property
    def manifest_hash(self) -> Optional[str]:
        return self._manifest_hash

    @property
    def commit_hash(self) -> Optional[str]:
        return self._commit_hash


def run(
    *,
    provider: str,
    model: str,
    db: Optional[str] = None,
    url: Optional[str] = None,
    token: Optional[str] = None,
    head: str = "main",
    agent_id: Optional[str] = None,
    model_parameters: Optional[dict] = None,
    sdk_version: Optional[str] = None,
    commit_message: Optional[str] = None,
    author: str = "agent",
    trace_id: Optional[str] = None,
    parent_span: Optional[str] = None,
    delegated_from: Optional[str] = None,
    subject: Optional[str] = None,
) -> AgentRun:
    """Context manager capturing one model invocation.

    Pass `url=` (+ `token=`) for the HTTP transport against `neleus-db serve`,
    or `db=` for the CLI transport against a local database directory.

    `trace_id` groups runs of one task across agent handoffs and model switches;
    `parent_span` is the parent run's manifest hash; `delegated_from` is the
    agent that handed off. Trace fields apply to the HTTP transport.
    """
    if url and db:
        raise NeleusError("pass either url= (HTTP) or db= (CLI), not both")
    if url and url.startswith(("neleus://", "neleuss://")):
        url, parsed = _parse_conn_str(url)
        token = token or parsed
    if url:
        transport: Any = HttpTransport(url, token)
    elif db:
        transport = CliTransport(db)
    else:
        raise NeleusError("pass url= (HTTP) or db= (CLI)")
    return AgentRun(
        transport=transport, head=head, provider=provider, model=model,
        agent_id=agent_id, model_parameters=model_parameters,
        sdk_version=sdk_version, commit_message=commit_message, author=author,
        trace_id=trace_id, parent_span=parent_span, delegated_from=delegated_from,
        subject=subject,
    )


def _to_bytes(value: str | bytes) -> bytes:
    return value.encode() if isinstance(value, str) else value


def _to_str(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.decode()
