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
