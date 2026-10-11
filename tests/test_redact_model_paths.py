"""Every model-bound prompt and persisted model artifact is redacted (synthetic markers only)."""
import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from fva.adapters import polaris
from fva.correlation.locate import SourceIndex
from fva.reasoning import model as model_mod
from fva.reasoning.assessor import assess, build_prompt
from fva.reasoning.model import CodexCliClient, ScriptedClient
from fva.redact import MASK, redact, redact_lines
from fva.schemas import EvidenceRecord, EvidenceType, PackageRef, Stance

BEARER = "Bearer FVAFAKE0123456789abcdef"
MARK = "FVAFAKE0123456789"
KEY = ["-----BEGIN PRIVATE KEY-----", "FVAFAKEKEYBODYAAAA", "FVAFAKEKEYBODYBBBB", "-----END PRIVATE KEY-----"]
SRC_HEAD = ["import x from 'x'", "export function f(req) {"]
SRC_TAIL = ["  return db.query(req.body.q)", "}"]


def _env(tmp_path, key_lines, description="", fix=None):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.ts").write_text("\n".join(SRC_HEAD + key_lines + SRC_TAIL) + "\n")
    line = len(SRC_HEAD) + len(key_lines) + 1
    row = {"candidate_id": "1", "tool": "SAST", "severity": "high", "issue_type": "SQL Injection",
           "cwe": "CWE-89", "checker": "SQLI", "location": "a.ts", "line": line}
    rows = tmp_path / "f.jsonl"
    rows.write_text(json.dumps(row) + "\n")
    f = polaris.load(rows)[1][0]
    update = {"description": description}
    if fix:
        update["scanner_metadata"] = {"fix_guidance": fix}
        update["package"] = PackageRef(name="p", version="1", ecosystem="npm", advisory_id="A")
    return f.model_copy(update=update), SourceIndex.build(src), line


def _ev(summary):
    return EvidenceRecord(evidence_id="e1", finding_ids=("x",), evidence_type=EvidenceType.static_source, method="m",
                          stance=Stance.neutral, summary=summary, collected_at=datetime.now(timezone.utc))


def test_redact_lines_masks_block_and_keeps_count():
    assert redact_lines(["a", *KEY, "b"]) == ["a", MASK, MASK, MASK, MASK, "b"]


def test_redact_lines_missing_end_masks_to_eof():
    assert redact_lines(["a", KEY[0], "FVAFAKEKEYBODYAAAA", "tail"]) == ["a", MASK, MASK, MASK]


def test_secret_free_prompt_is_unchanged(tmp_path):
    f, idx, _ = _env(tmp_path, [], description="plain description")
    prompt = build_prompt(f, idx, [_ev("plain summary")], [])
    assert redact(prompt) == prompt and "plain description" in prompt and "plain summary" in prompt


@pytest.mark.parametrize("where", ["description", "fix", "evidence"])
def test_bearer_marker_absent_from_prompt_and_cache(tmp_path, where):
    f, idx, _ = _env(tmp_path, [], description=f"see {BEARER}" if where == "description" else "",
                     fix=f"use {BEARER}" if where == "fix" else None)
    ev = [_ev(f"saw {BEARER}")] if where == "evidence" else []
    client = ScriptedClient([json.dumps({"claims": [], "confidence": "low", "x": BEARER})])
    assess(f, idx, client, source_content_sha256="0" * 64, profile_id="p", evidence=ev, cache_dir=tmp_path / "cache")
    assert all(MARK not in s and MARK not in u for s, u in client.prompts)
    files = list((tmp_path / "cache").iterdir())
    assert files and all(MARK not in p.read_text(encoding="utf-8") for p in files)


@pytest.mark.parametrize("key", [KEY, KEY[:-1]], ids=["closed", "missing-end"])
def test_multiline_key_never_reaches_model(tmp_path, key):
    f, idx, _ = _env(tmp_path, key)
    client = ScriptedClient(['{"claims": [], "confidence": "low"}'])
    assess(f, idx, client, source_content_sha256="0" * 64, profile_id="p")
    user = client.prompts[0][1]
    assert "FVAFAKEKEYBODY" not in user and "BEGIN PRIVATE" not in user and MASK in user


def test_citation_of_redacted_line_and_code_after_it_verifies(tmp_path):
    f, idx, line = _env(tmp_path, KEY)
    cites = [{"path": "a.ts", "line": line, "quote": "db.query(req.body.q)"},
             {"path": "a.ts", "line": 3, "quote": MASK}]
    reply = {"claims": [{"statement": "s", "stance": "supports", "suggested_reason_code": None, "citations": cites}],
             "confidence": "high"}
    res = assess(f, idx, ScriptedClient([json.dumps(reply)]), source_content_sha256="0" * 64, profile_id="p")
    assert len(res.accepted[0]["citations"]) == 2 and not res.rejected


def test_response_roundtrip_keeps_schema_keys_and_masks_values(tmp_path):
    f, idx, line = _env(tmp_path, [])
    reply = {"claims": [{"statement": f"cookie: {BEARER}", "stance": "supports", "suggested_reason_code": None,
                         "citations": [{"path": "a.ts", "line": line, "quote": "db.query(req.body.q)"}]}],
             "confidence": "high"}
    res = assess(f, idx, ScriptedClient([json.dumps(reply)]), source_content_sha256="0" * 64, profile_id="p",
                 cache_dir=tmp_path / "cache")
    assert not res.unparseable and res.confidence == "high" and len(res.accepted) == 1
    assert MARK not in json.dumps(res.accepted)


def test_cli_failure_log_and_error_are_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("FVA_CLI_LOG_DIR", str(tmp_path / "logs"))
    client = CodexCliClient(command=f"{sys.executable} exec -")

    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 2, stdout=f"Authorization: {BEARER}\n", stderr=f"token {BEARER}")
    monkeypatch.setattr(model_mod.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError) as e:
        client.complete("sys", "user")
    assert MARK not in str(e.value)
    logs = list((tmp_path / "logs").iterdir())
    assert logs and all(MARK not in p.read_text(encoding="utf-8") for p in logs)
