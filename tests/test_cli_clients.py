import json
import os
import stat
import sys
from pathlib import Path

import pytest

from fva.reasoning.model import ClaudeCodeClient, CodexCliClient

REPLY = {"claims": [], "confidence": "low"}


def _exe(tmp_path, name, body):
    p = tmp_path / "bin" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(f"#!{sys.executable}\n{body}")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p.parent


@pytest.mark.skipif(os.name == "nt", reason="shebang stand-ins are POSIX-only")
def test_codex_reads_last_message_file_and_runs_in_empty_dir(tmp_path, monkeypatch):
    bindir = _exe(tmp_path, "codex", f"""
import sys, os, json
args = sys.argv[1:]
assert args[:2] == ["exec", "--skip-git-repo-check"] and args[-1] == "-"
prompt = sys.stdin.read()
assert "FINDING" in prompt and os.listdir(".") == []
out = args[args.index("--output-last-message") + 1]
open(out, "w").write({json.dumps(json.dumps(REPLY))})
print("agent chatter that must be ignored")
""")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    assert json.loads(CodexCliClient().complete("sys", "FINDING x")) == REPLY


@pytest.mark.skipif(os.name == "nt", reason="shebang stand-ins are POSIX-only")
def test_claude_code_uses_stdout(tmp_path, monkeypatch):
    bindir = _exe(tmp_path, "claude", f"import sys; sys.stdin.read(); print({json.dumps(json.dumps(REPLY))})")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    assert json.loads(ClaudeCodeClient().complete("sys", "u")) == REPLY


@pytest.mark.skipif(os.name == "nt", reason="shebang stand-ins are POSIX-only")
def test_cli_failure_shows_tail_and_saves_log(tmp_path, monkeypatch):
    bindir = _exe(tmp_path, "codex", "import sys; sys.stderr.write('echo of prompt\\n' * 500 + 'ERROR: not logged in'); sys.exit(2)")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FVA_CLI_LOG_DIR", str(tmp_path / "logs"))
    with pytest.raises(RuntimeError, match="not logged in"):
        CodexCliClient().complete("s", "u")
    assert "not logged in" in next((tmp_path / "logs").glob("*.log")).read_text()


def test_missing_cli(monkeypatch):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(SystemExit, match="not found"):
        CodexCliClient()


@pytest.mark.skipif(os.name == "nt", reason="shebang stand-ins are POSIX-only")
def test_model_flag_passed_before_stdin_marker(tmp_path, monkeypatch):
    bindir = _exe(tmp_path, "codex", f"""
import sys
args = sys.argv[1:]
assert args[-3:] == ["-m", "some-model", "-"], args
sys.stdin.read()
open(args[args.index("--output-last-message") + 1], "w").write('{{"claims": []}}')
""")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    c = CodexCliClient(model="some-model")
    assert c.model_id == "codex-cli:some-model" and c.complete("s", "u") == '{"claims": []}'


def _fake_codex(monkeypatch, stderr, reply='{"claims": [], "confidence": "low"}'):
    import shutil
    import subprocess
    seen = {}

    def run(argv, **kw):
        seen["argv"] = argv
        out = argv[argv.index("--output-last-message") + 1]
        open(out, "w", encoding="utf-8").write(reply)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr=stderr)
    monkeypatch.setattr(shutil, "which", lambda name: name)
    monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_codex_enforces_schema_and_parses_model_and_tokens(monkeypatch):
    from fva.reasoning.model import SCHEMA_FILE
    seen = _fake_codex(monkeypatch, "workdir: x\nmodel: gpt-6-luna\n\x1b[2mtokens used\x1b[0m\n11,513\n")
    c = CodexCliClient(model="gpt-6-luna")
    c.complete("s", "u")
    argv = seen["argv"]
    assert argv[argv.index("--output-schema") + 1] == str(SCHEMA_FILE) and json.loads(SCHEMA_FILE.read_text())
    assert c.last_reported_model == "gpt-6-luna" and c.last_tokens == 11513 and c.cache_tag == "schema-v1"


def test_codex_without_footer_resets_previous_values(monkeypatch):
    _fake_codex(monkeypatch, "model: gpt-6-sol\ntokens used\n900\n")
    c = CodexCliClient()
    c.complete("s", "u")
    _fake_codex(monkeypatch, "")
    c.complete("s", "u")
    assert c.last_reported_model is None and c.last_tokens is None


def test_custom_codex_command_without_schema_has_no_cache_tag(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: name)
    monkeypatch.setenv("FVA_CODEX_CMD", "codex exec --output-last-message {out} -")
    assert CodexCliClient().cache_tag == ""
