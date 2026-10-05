import json
import shutil
import subprocess

import pytest

from fva import pipeline
from fva.reasoning import pricing
from fva.reasoning.model import CodexCliClient, ScriptedClient
from fva.schemas import DeploymentProfile

LUNA = {"input_tokens": 23969, "cached_input_tokens": 20224, "output_tokens": 205}
SOL = {"input_tokens": 24236, "cached_input_tokens": 21344, "output_tokens": 238}
REPLY = '{"claims": [], "confidence": "low"}'


def test_dollar_math():
    assert pricing.cost(LUNA, "gpt-6-luna") == pytest.approx(0.00067924)
    assert pricing.cost({**SOL, "reasoning_output_tokens": 99}, "gpt-6-sol") == pytest.approx(0.0124328)
    assert pricing.cost(LUNA, "gpt-9") is None and pricing.cost(None, "gpt-6-sol") is None
    assert pricing.cost(LUNA, "codex-cli:gpt-6-luna") == pytest.approx(0.00067924)


def test_load_prices(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"m": {"input": 1, "cached_input": 0, "output": 2}}))
    assert pricing.cost({"input_tokens": 1_000_000, "output_tokens": 1_000_000}, "m", pricing.load_prices(p)) == 3
    p.write_text(json.dumps({"m": {"input": 1}}))
    with pytest.raises(ValueError):
        pricing.load_prices(p)


def _events(usage=True, text=REPLY):
    rows = [{"type": "thread.started", "thread_id": "T1"}, {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}}]
    if usage:
        rows.append({"type": "turn.completed", "usage": {**LUNA, "reasoning_output_tokens": 64, "note": "x"}})
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def _fake_codex(monkeypatch, stdout, stderr="", write_last=True):
    seen = {}

    def run(argv, **kw):
        seen["argv"] = argv
        if write_last:
            open(argv[argv.index("--output-last-message") + 1], "w", encoding="utf-8").write(REPLY)
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(shutil, "which", lambda name: name)
    monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_codex_usage_and_session_model(monkeypatch, tmp_path):
    session = tmp_path / "sessions" / "2026" / "10" / "rollout-T1.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(json.dumps({"type": "session_meta"}) + "\n"
                       + json.dumps({"type": "turn_context", "payload": {"model": "gpt-6-luna"}}) + "\n")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    seen = _fake_codex(monkeypatch, _events())
    c = CodexCliClient()
    c.complete("s", "u")
    assert seen["argv"].count("--json") == 1 and c.cache_tag == "schema-v1"
    assert c.last_usage == {**LUNA, "reasoning_output_tokens": 64}
    assert c.last_reported_model == "gpt-6-luna" and c.last_tokens is None


def test_codex_header_model_wins_over_session(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    _fake_codex(monkeypatch, _events(), stderr="model: gpt-6-sol\n")
    c = CodexCliClient()
    c.complete("s", "u")
    assert c.last_reported_model == "gpt-6-sol"


def test_missing_turn_completed_means_no_usage(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    c = CodexCliClient()
    _fake_codex(monkeypatch, _events())
    c.complete("s", "u")
    _fake_codex(monkeypatch, _events(usage=False))
    c.complete("s", "u")
    assert c.last_usage is None


def test_last_agent_message_when_no_output_file(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    _fake_codex(monkeypatch, _events(), write_last=False)
    assert CodexCliClient().complete("s", "u") == REPLY


def test_audited_client_keeps_audit_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    _fake_codex(monkeypatch, _events())
    c = CodexCliClient(audit=True)
    c.complete("s", "u")
    assert c.last_audit["complete"] and c.last_audit["thread_id"] == "T1" and c.last_audit["tool_items"] == []


class Reporting(ScriptedClient):
    last_reported_model, last_tokens, last_usage = "gpt-6-luna", None, LUNA


def _run(tmp_path, client, out):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "server.ts").write_text("import './a'\n")
    (src / "a.ts").write_text("sequelize.query(q)\n")
    fj = tmp_path / "f.jsonl"
    fj.write_text(json.dumps({"candidate_id": "A", "tool": "SAST", "severity": "high", "issue_type": "SQLi",
                              "cwe": "CWE-89", "location": "a.ts", "line": 1}) + "\n")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    return pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=client, out_dir=tmp_path / out,
                        cache_dir=tmp_path / "cache", log=lambda *_: None)


def test_summary_cost_fresh_then_cached(tmp_path):
    fresh = _run(tmp_path, Reporting([REPLY]), "o1")["cost"]
    assert fresh == {"fresh_calls": 1, "input_tokens": 23969, "cached_input_tokens": 20224, "output_tokens": 205,
                     "usd": 0.000679, "calls_without_usage": 0, "unpriced_calls": 0, "usd_when_first_made": 0.0}
    s = _run(tmp_path, Reporting([]), "o2")
    assert s["cost"]["fresh_calls"] == 0 and s["cost"]["usd"] == 0 and s["cost"]["usd_when_first_made"] == 0.000679
    assert s["tiers"]["fixed"]["cost"]["usd_when_first_made"] == 0.000679
    assert json.loads((tmp_path / "o2" / "summary.json").read_text())["cost"] == s["cost"]


def test_summary_cost_without_usage_or_price(tmp_path):
    class NoUsage(Reporting):
        last_usage = None

    class Unknown(Reporting):
        last_reported_model = "gpt-9"
    c = _run(tmp_path, NoUsage([REPLY]), "o1")["cost"]
    assert c["fresh_calls"] == 1 and c["calls_without_usage"] == 1 and c["usd"] == 0
    shutil.rmtree(tmp_path / "cache")
    c = _run(tmp_path, Unknown([REPLY]), "o2")["cost"]
    assert c["unpriced_calls"] == 1 and c["input_tokens"] == 23969 and c["usd"] == 0
