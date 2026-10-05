"""Swappable model clients. The assessor only depends on the ModelClient protocol, so a
local/self-hosted model can replace the hosted API without touching reasoning code."""
from __future__ import annotations

import json
import os
import threading
import urllib.request
from typing import Protocol


class ModelClient(Protocol):
    model_id: str

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str: ...


class AnthropicClient:
    """Claude via the Messages API. Key from ANTHROPIC_API_KEY. Temperature 0 for reproducibility."""

    def __init__(self, model_id: str = "claude-sonnet-5", api_key: str | None = None,
                 base_url: str = "https://api.anthropic.com"):
        self.model_id = model_id
        self._key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._key:
            raise SystemExit("Set ANTHROPIC_API_KEY to use AnthropicClient")
        self._url = base_url.rstrip("/") + "/v1/messages"

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        body = {"model": self.model_id, "max_tokens": max_tokens, "temperature": 0, "system": system,
                "messages": [{"role": "user", "content": user}]}
        req = urllib.request.Request(self._url, json.dumps(body).encode(), {
            "x-api-key": self._key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            msg = json.loads(r.read())
        return "".join(b.get("text", "") for b in msg.get("content", []) if b.get("type") == "text")


class OpenAICompatibleClient:
    """Any OpenAI-compatible chat endpoint (vLLM, Ollama, LM Studio...) for local/self-hosted models."""

    def __init__(self, model_id: str, base_url: str, api_key: str | None = None):
        self.model_id = model_id
        self._url = base_url.rstrip("/") + "/v1/chat/completions"
        self._key = api_key or os.environ.get("FVA_LOCAL_MODEL_KEY", "")

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        body = {"model": self.model_id, "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        h = {"content-type": "application/json", **({"authorization": f"Bearer {self._key}"} if self._key else {})}
        with urllib.request.urlopen(urllib.request.Request(self._url, json.dumps(body).encode(), h), timeout=300) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]


class ScriptedClient:
    """Deterministic client for tests: returns queued responses in order (thread-safe)."""

    def __init__(self, responses: list[str], model_id: str = "scripted"):
        self.model_id, self._responses, self.prompts = model_id, list(responses), []
        self._lock = threading.Lock()

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        with self._lock:
            self.prompts.append((system, user))
            return self._responses.pop(0)


# ------------------------------------------------------------------------------------------
# Subscription-backed CLI clients (run on the user's machine where the CLI is logged in)
# ------------------------------------------------------------------------------------------
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

SCHEMA_FILE = Path(__file__).with_name("assessment.schema.json")  # reply shape, for CLIs that enforce one
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _jsonl(text: str) -> list[dict | None]:
    """One entry per stdout line: the parsed event, or None when the line is not a JSON object."""
    rows = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        rows.append(event if isinstance(event, dict) else None)
    return rows


def _session_model(thread: str) -> str | None:
    """Model named in this thread's own Codex session file; never other sessions or config defaults."""
    sessions = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "sessions"
    model = None
    for path in sessions.glob(f"**/*{thread}.jsonl"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("type") == "turn_context":
                model = (row.get("payload") or {}).get("model") or model
    return model


class _CliClient:
    """Runs a local agent CLI non-interactively in an EMPTY temp directory, prompt on stdin.

    The empty working directory means the agent has no repository to browse: it sees only
    the redacted prompt we send. Override the command with an env var if your CLI version
    uses different flags (the first run doubles as a smoke test).
    """

    env_var = ""
    default_cmd = ""
    model_id = "cli"

    model_flag = "-m"

    # Per-thread, so one client can serve parallel pipeline workers: the assessor reads these right after
    # complete() on the same thread. None until a call on this thread has set them.
    #   last_reported_model: str | None  parsed from the CLI's own `model: <name>` header line
    #   last_tokens: int | None          parsed from the CLI's `tokens used` footer, when it prints one
#   last_usage: dict | None          int fields of the `turn.completed` usage in --json output, else None
    @property
    def last_reported_model(self) -> str | None:
        return getattr(self._local, "last_reported_model", None)

    @last_reported_model.setter
    def last_reported_model(self, value: str | None) -> None:
        self._local.last_reported_model = value

    @property
    def last_tokens(self) -> int | None:
        return getattr(self._local, "last_tokens", None)

    @last_tokens.setter
    def last_tokens(self, value: int | None) -> None:
        self._local.last_tokens = value

    @property
    def last_usage(self) -> dict | None:
        return getattr(self._local, "last_usage", None)

    @last_usage.setter
    def last_usage(self, value: dict | None) -> None:
        self._local.last_usage = value

    def __init__(self, command: str | None = None, timeout: int = 600, model: str | None = None,
                 schema_file: Path | None = None, audit: bool = False):
        self._local = threading.local()
        self.schema_file = schema_file or SCHEMA_FILE
        self.audit = audit
        cmd = command or os.environ.get(self.env_var) or self.default_cmd
        self._argv = shlex.split(cmd, posix=(os.name != "nt"))
        if audit and isinstance(self, CodexCliClient):
            if "exec" not in self._argv:
                raise ValueError("audited Codex command must contain the exec subcommand")
            at = self._argv.index("exec") + 1
            end = self._argv.index("--", at) if "--" in self._argv[at:] else len(self._argv)
            options = self._argv[at:end]
            flags = [flag for flag in ("--json", "--ignore-user-config") if flag not in options]
            self._argv[at:at] = flags
        if model:  # insert right after the subcommand words, before the trailing '-' (stdin) if present
            at = len(self._argv) - 1 if self._argv[-1] == "-" else len(self._argv)
            if "--" in self._argv:
                at = self._argv.index("--")
            self._argv[at:at] = [self.model_flag, model]
            self.model_id = f"{self.model_id}:{model}"
        exe = shutil.which(self._argv[0])
        if exe is None:
            raise SystemExit(f"'{self._argv[0]}' not found on PATH (set {self.env_var} to override)")
        self._argv[0] = exe
        self._timeout = timeout

    def _run(self, prompt: str, workdir: Path) -> str:
        argv = [a.replace("{out}", str(workdir / "last_message.txt")).replace("{schema}", str(self.schema_file))
                for a in self._argv]
        self.last_reported_model = self.last_tokens = self.last_usage = None
        self._local.last_audit = None
        r = subprocess.run(argv, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           cwd=workdir, timeout=self._timeout)
        if r.returncode != 0:
            log_dir = Path(os.environ.get("FVA_CLI_LOG_DIR", "data/logs"))
            log_dir.mkdir(parents=True, exist_ok=True)
            log = log_dir / f"{Path(argv[0]).stem}-{workdir.name}.log"
            log.write_text(f"argv: {argv}\nexit: {r.returncode}\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}",
                           encoding="utf-8")
            tail = "\n".join(((r.stderr or "") + "\n" + (r.stdout or "")).strip().splitlines()[-12:])
            raise RuntimeError(f"{Path(argv[0]).name} exited {r.returncode} (full log: {log}):\n{tail}")
        log = _ANSI.sub("", f"{r.stderr}\n{r.stdout}")
        m = re.search(r"^model:\s*(\S+)", log, re.M)
        self.last_reported_model = m.group(1) if m else None
        t = re.search(r"^tokens used\s*\n\s*([\d,]+)", log, re.M)
        self.last_tokens = int(t.group(1).replace(",", "")) if t else None
        rows = _jsonl(r.stdout)
        events = [e for e in rows if e is not None]
        thread = next((e.get("thread_id") for e in events if e.get("type") == "thread.started"), None)
        if not self.last_reported_model and thread:
            self.last_reported_model = _session_model(thread)
        done = [e for e in events if e.get("type") == "turn.completed"]
        usage = done[0].get("usage") if done else None
        usage = {k: v for k, v in usage.items() if isinstance(v, int)} if isinstance(usage, dict) else None
        self.last_usage = usage or None
        if self.audit:
            tools, unknown = [], []
            for event in rows:
                if event is None:
                    unknown.append("non-JSON event")
                    continue
                kind = event.get("type")
                if kind not in {"thread.started", "turn.started", "turn.completed", "item.started",
                                "item.updated", "item.completed", "error", "turn.failed"}:
                    unknown.append(str(kind))
                item = event.get("item", {})
                if item and item.get("type") not in {"agent_message", "reasoning"}:
                    tools.append(item.get("type", "unknown"))
            self._local.last_audit = {"thread_id": thread, "tool_items": tools, "unknown_events": unknown,
                                      "usage": done[0].get("usage") if done else None,
                                      "observed_model": self.last_reported_model, "complete": bool(done)}
        out_file = workdir / "last_message.txt"
        if out_file.exists():
            return out_file.read_text(encoding="utf-8")
        texts = [e["item"]["text"] for e in events if e.get("type") == "item.completed"
                 and isinstance(e.get("item"), dict) and e["item"].get("type") == "agent_message"
                 and isinstance(e["item"].get("text"), str)]
        return texts[-1] if texts else r.stdout

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        prompt = (f"{system}\n\n---\n\n{user}\n\nRespond with the JSON object only. Do not run commands or read files. "
                  "Do not delegate or spawn sub-agents; answer this yourself.")
        with tempfile.TemporaryDirectory(prefix="fva-model-") as d:
            return self._run(prompt, Path(d))


class CodexCliClient(_CliClient):
    """OpenAI Codex CLI on a ChatGPT/Codex subscription login: `codex exec`, read-only sandbox,
    final reply constrained to the assessment JSON schema."""

    env_var = "FVA_CODEX_CMD"
    default_cmd = ("codex exec --skip-git-repo-check --sandbox read-only --output-schema {schema} "
                   "--output-last-message {out} --json -")
    model_id = "codex-cli"

    @property
    def cache_tag(self) -> str:
        if not any("{schema}" in a for a in self._argv):
            return ""
        if self.schema_file == SCHEMA_FILE:
            return "schema-v1"
        import hashlib
        return "schema:" + hashlib.sha256(self.schema_file.read_bytes()).hexdigest()

    @property
    def last_audit(self):
        return getattr(self._local, "last_audit", None)


class ClaudeCodeClient(_CliClient):
    """Claude Code on a Claude subscription login: `claude -p` (print mode), no tools."""

    env_var = "FVA_CLAUDE_CMD"
    default_cmd = "claude -p --output-format text"
    model_id = "claude-code-cli"
    model_flag = "--model"
