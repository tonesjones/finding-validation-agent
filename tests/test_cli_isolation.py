import json
import subprocess
from types import SimpleNamespace

import pytest

from fva import __main__ as cli, pipeline
from fva.reasoning import isolation, model as m

OLD_CODEX_DEFAULT = ("codex exec --skip-git-repo-check --sandbox read-only --output-schema {schema} "
                     "--output-last-message {out} --json -")


@pytest.fixture
def fake_run(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: name)
    monkeypatch.delenv("FVA_CODEX_CMD", raising=False)
    monkeypatch.delenv("FVA_CLAUDE_CMD", raising=False)
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_claude_default_argv_has_empty_tools_arg(fake_run):
    c = m.ClaudeCodeClient()
    c.complete("s", "u")
    assert fake_run[0][0] == ["claude", "-p", "--output-format", "text", "--tools", "",
                              "--strict-mcp-config", "--permission-prompts", "none"]
    assert c.isolation == "enforced"


def test_codex_default_argv(fake_run):
    c = m.CodexCliClient()
    c.complete("s", "u")
    argv = fake_run[0][0]
    assert argv[:2] == ["codex", "exec"]
    assert "--ignore-user-config" in argv and argv[argv.index("--sandbox") + 1] == "read-only"
    assert argv[-1] == "-" and c.isolation == "enforced"


def test_env_is_minimal(fake_run, monkeypatch):
    monkeypatch.setenv("POLARIS_ACCESS_TOKEN", "x")
    monkeypatch.setenv("FVA_TEST_SECRET", "y")
    m.CodexCliClient().complete("s", "u")
    env = {k.upper() for k in fake_run[0][1]["env"]}
    assert "PATH" in env
    assert not {"POLARIS_ACCESS_TOKEN", "FVA_TEST_SECRET"} & env


def test_override_command_is_unverified(fake_run, monkeypatch):
    assert m.ClaudeCodeClient(command="claude -p").isolation == "unverified"
    monkeypatch.setenv("FVA_CODEX_CMD", "codex exec -")
    assert m.CodexCliClient().isolation == "unverified"


def test_cache_key_inputs_unchanged_by_new_flags(fake_run):
    # The assessor key is built from model_id, the prompt hash and cache_tag only (never argv).
    new, old = m.CodexCliClient(), m.CodexCliClient(command=OLD_CODEX_DEFAULT)
    assert (new.model_id, new.cache_tag) == (old.model_id, old.cache_tag) == ("codex-cli", "schema-v1")


def test_codex_default_turns_tool_features_off(fake_run):
    m.CodexCliClient().complete("s", "u")
    argv = fake_run[0][0]
    disabled = {argv[i + 1] for i, a in enumerate(argv) if a == "--disable"}
    assert disabled == set(m.CODEX_DISABLED_FEATURES)
    assert {"apps", "shell_tool", "unified_exec", "code_mode_host"} <= disabled and argv[-1] == "-"


def _events(*items):
    rows = [{"type": "thread.started", "thread_id": "T"}]
    rows += [{"type": "item.completed", "item": {"id": str(i), "type": t, "text": "x"}} for i, t in enumerate(items)]
    return "\n".join(json.dumps(r) for r in rows + [{"type": "turn.completed", "usage": {}}])


@pytest.mark.parametrize("item", ["command_execution", "mcp_tool_call", "collab_tool_call", "file_change",
                                  "web_search", "some_new_tool"])
def test_tool_use_rejects_the_answer(monkeypatch, item):
    monkeypatch.setattr(m.shutil, "which", lambda name: name)
    monkeypatch.delenv("FVA_CODEX_CMD", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: SimpleNamespace(
        returncode=0, stdout=_events("reasoning", item, "agent_message"), stderr=""))
    with pytest.raises(m.ToolUseError, match=item):
        m.CodexCliClient().complete("s", "u")


def test_messages_reasoning_and_errors_are_not_tool_use(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: name)
    monkeypatch.delenv("FVA_CODEX_CMD", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: SimpleNamespace(
        returncode=0, stdout=_events("reasoning", "error", "todo_list", "agent_message"), stderr=""))
    assert m.CodexCliClient().complete("s", "u") == "x"


class Canary:
    model_id, isolation = "fake", "enforced"

    def __init__(self, mode):
        self.mode = mode

    def complete(self, system, user):
        if self.mode == "tool":
            raise m.ToolUseError("codex used tools during assessment: command_execution")
        path = user.split("'")[1]
        return open(path, encoding="utf-8").read() if self.mode == "leak" else "CANNOT_READ"


@pytest.mark.parametrize("mode, passed", [("refuse", True), ("leak", False), ("tool", False)])
def test_isolation_check(mode, passed, tmp_path):
    r = isolation.check(Canary(mode), "codex", "codex-cli 1.0")
    assert r["passed"] is passed and len(r["probes"]) == len(isolation.PROBES)
    text = isolation.save(r, tmp_path).read_text(encoding="utf-8")
    assert "FVA-CANARY-" not in text
    assert isolation.passed_for("codex", "codex-cli 1.0", tmp_path) is passed
    assert not isolation.passed_for("codex", "codex-cli 1.1", tmp_path)


def test_private_source_gate(fake_run, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline, "_cli_version", lambda exe: "codex-cli 1.0")
    with pytest.raises(SystemExit, match="check-isolation"):
        cli.check_private_source("codex", None)
    isolation.save(isolation.check(Canary("refuse"), "codex", "codex-cli 1.0"))
    cli.check_private_source("codex", None)
    cli.check_private_source("claude-code", None)
    cli.check_private_source("anthropic", None)
    monkeypatch.setenv("FVA_CODEX_CMD", "codex exec -")
    with pytest.raises(SystemExit, match="custom"):
        cli.check_private_source("codex", None)
