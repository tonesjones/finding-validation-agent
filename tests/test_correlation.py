import os
import subprocess
from pathlib import Path

import pytest

from fva.adapters import mapping
from fva.correlation.locate import SourceIndex, locate, to_evidence
from fva.correlation.source_pin import pin
from fva.redact import redact
from fva.schemas import Stance

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "login.ts").write_bytes(b"a\r\nb\r\nconst password = 'hunter2'\r\nd\r\n")
    (tmp_path / "server.ts").write_text("x\n")
    return tmp_path


def test_pin_is_line_ending_neutral(tmp_path, repo):
    lf = tmp_path.parent / (tmp_path.name + "_lf")
    (lf / "routes").mkdir(parents=True)
    (lf / "routes" / "login.ts").write_bytes(b"a\nb\nconst password = 'hunter2'\nd\n")
    (lf / "server.ts").write_text("x\n")
    assert pin(repo).content_sha256 == pin(lf).content_sha256
    assert pin(repo).vcs_commit is None


def test_pin_ignores_untracked_and_leaves_no_lock(repo):
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    g("init", "-q"); g("add", "."); g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i")
    before = pin(repo)
    (repo / "output.json").write_text("{}")  # untracked junk
    after = pin(repo)
    assert before.content_sha256 == after.content_sha256 and after.vcs_dirty is False
    assert not (repo / ".git" / "index.lock").exists()


def _finding(path, line, cwe=""):
    import json, tempfile
    d = Path(tempfile.mkdtemp())
    (d / "f.jsonl").write_text(json.dumps({"candidate_id": "1", "tool": "SAST", "severity": "low",
                                            "issue_type": "t", "location": path, "line": line, "cwe": cwe}) + "\n")
    from fva.adapters import polaris
    return polaris.load(d / "f.jsonl")[1][0]


@pytest.mark.parametrize("path,line,status", [
    ("routes/login.ts", 3, "exact"),
    ("routes/login.ts", 99, "line_out_of_range"),
    ("app/routes/login.ts", 3, "relocated"),
    ("nope.ts", 1, "path_missing"),
])
def test_locate_statuses(repo, path, line, status):
    r = locate(_finding(path, line), SourceIndex.build(repo))
    assert r.status == status


def test_snippet_redacted_and_evidence_neutral(repo):
    r = locate(_finding("routes/login.ts", 3, "CWE-798"), SourceIndex.build(repo))
    assert "hunter2" not in r.snippet and "[REDACTED]" in r.snippet and "\r" not in r.snippet
    e = to_evidence(r, source_content_sha256="0" * 64)
    assert e.stance is Stance.neutral and "hunter2" not in e.summary


@pytest.mark.parametrize("raw", [
    "Authorization: Bearer abcdefghijklmnop",
    "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig",
    'apiKey: "sk_live_abcdefghijkl"',
    "Cookie: session=abc; other=def",
    "AKIAABCDEFGHIJKLMNOP",
])
def test_redact_patterns(raw):
    out = redact(raw)
    assert "[REDACTED]" in out
    for secret in ("abcdefghijklmnop", "eyJzdWIi", "sk_live_abc", "session=abc", "AKIAABCD"):
        assert secret not in out


JUICE = os.environ.get("FVA_JUICESHOP_SRC")
LEDGER = Path(__file__).resolve().parents[1] / "data" / "poc-report" / "final-validation-ledger.jsonl"


@pytest.mark.skipif(not (JUICE and LEDGER.exists()), reason="set FVA_JUICESHOP_SRC and provide the private ledger")
def test_all_poc_sast_findings_locate_exactly():
    from fva.adapters import polaris
    _, fs = polaris.load(LEDGER)
    idx = SourceIndex.build(Path(JUICE))
    statuses = {locate(f, idx).status for f in fs if f.location}
    assert statuses == {"exact"}


def test_git_output_decoding_is_locale_independent(tmp_path):
    """Regression: on Windows (cp1252) non-ASCII file names crashed git output decoding."""
    import sys
    (tmp_path / "ᓚᘏᗢ-cat.jpg").write_bytes(b"x")
    (tmp_path / "a.ts").write_text("x\n")
    g = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)
    g("init", "-q"); g("add", "."); g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i")
    code = ("import sys; from pathlib import Path; from fva.correlation.source_pin import _git; "
            f"out = _git(Path({str(tmp_path)!r}), 'ls-files', '-z'); assert out is not None and 'a.ts' in out")
    env = {**os.environ, "LC_ALL": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0",
           "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    r = subprocess.run([sys.executable, "-X", "utf8=0", "-c", code], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
