"""Swappable model clients. The assessor only depends on the ModelClient protocol, so a
local/self-hosted model can replace the hosted API without touching reasoning code."""
from __future__ import annotations

import json
import os
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
    """Deterministic client for tests: returns queued responses in order."""

    def __init__(self, responses: list[str], model_id: str = "scripted"):
        self.model_id, self._responses, self.prompts = model_id, list(responses), []

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        self.prompts.append((system, user))
        return self._responses.pop(0)


# ------------------------------------------------------------------------------------------
# Subscription-backed CLI clients (run on the user's machine where the CLI is logged in)
# ------------------------------------------------------------------------------------------
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


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

    def __init__(self, command: str | None = None, timeout: int = 600, model: str | None = None):
        cmd = command or os.environ.get(self.env_var) or self.default_cmd
        self._argv = shlex.split(cmd, posix=(os.name != "nt"))
        if model:  # insert right after the subcommand words, before the trailing '-' (stdin) if present
            at = len(self._argv) - 1 if self._argv[-1] == "-" else len(self._argv)
            self._argv[at:at] = [self.model_flag, model]
            self.model_id = f"{self.model_id}:{model}"
        exe = shutil.which(self._argv[0])
        if exe is None:
            raise SystemExit(f"'{self._argv[0]}' not found on PATH (set {self.env_var} to override)")
        self._argv[0] = exe
        self._timeout = timeout

    def _run(self, prompt: str, workdir: Path) -> str:
        argv = [a.replace("{out}", str(workdir / "last_message.txt")) for a in self._argv]
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
        out_file = workdir / "last_message.txt"
        return out_file.read_text(encoding="utf-8") if out_file.exists() else r.stdout

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        prompt = f"{system}\n\n---\n\n{user}\n\nRespond with the JSON object only. Do not run commands or read files."
        with tempfile.TemporaryDirectory(prefix="fva-model-") as d:
            return self._run(prompt, Path(d))


class CodexCliClient(_CliClient):
    """OpenAI Codex CLI on a ChatGPT/Codex subscription login: `codex exec`, read-only sandbox."""

    env_var = "FVA_CODEX_CMD"
    default_cmd = "codex exec --skip-git-repo-check --sandbox read-only --output-last-message {out} -"
    model_id = "codex-cli"


class ClaudeCodeClient(_CliClient):
    """Claude Code on a Claude subscription login: `claude -p` (print mode), no tools."""

    env_var = "FVA_CLAUDE_CMD"
    default_cmd = "claude -p --output-format text"
    model_id = "claude-code-cli"
    model_flag = "--model"
