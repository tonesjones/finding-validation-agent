import subprocess
from types import SimpleNamespace

import pytest

from fva.reasoning import model as m

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
