import hashlib
import json
import subprocess

import pytest

from fva.discovery import FIXED_MODEL, discover, freeze_source
from fva.evaluation import (digest, preflight, prepare_cases, raw_verdict, run_cases,
                            score_cases, verify_seal, write_json)
from fva.reasoning.model import CodexCliClient, ScriptedClient
from fva.redact import redact
from fva.schemas import DeploymentProfile, Finding


class AuditedClient(ScriptedClient):
    last_reported_model = FIXED_MODEL
    last_audit = {"complete": True, "tool_items": [], "unknown_events": [], "usage": {"output_tokens": 5}}


@pytest.fixture
def pilot(tmp_path):
    source = tmp_path / "app"
    source.mkdir()
    (source / "routes.js").write_text("import * as search from './search.js'\napp.get('/search', search.run)\n")
    (source / "search.js").write_text("export const run = (req) => db.query(req.query.q)\n")
    (source / "package.json").write_text('{"dependencies":{"demo":"1.0.0"}}')
    (source / "planting-ledger.md").write_text("DO NOT READ GOLD SECRET")
    profile = DeploymentProfile(profile_id="demo", name="demo", language_packs=("node",), entrypoints=("routes.js",))
    return source, profile


def finding(fid="s1", tool="polaris"):
    return Finding(finding_id=fid, run_id="r", source_tool=tool, source_finding_id=fid,
                   rule_id="sqli", title="SQL injection", severity="high", finding_type="sast", cwe=("CWE-89",),
                   location={"path": "search.js", "start_line": 1}, raw_evidence_ref="raw:sha256:" + "0" * 64)


def prep(pilot, tmp_path, members=None):
    source, profile = pilot
    out = tmp_path / "prepared"
    expected = tmp_path / "expected.json"
    write_json(expected, [{"method": "GET", "path": "/search", "handlers": ["search.js"]}])
    report = preflight(source, profile, out, expected_routes=expected)
    canonical = tmp_path / "canonical.jsonl"
    canonical.write_text("".join(f.model_dump_json() + "\n" for f in members or [finding()]))
    prepare_cases(source, profile, out, report, canonical_paths=[canonical])
    return out


def response(quote="db.query(req.query.q)", stance="supports"):
    return json.dumps({"claims": [{"statement": "query input reaches query", "stance": stance,
                                  "suggested_reason_code": None,
                                  "citations": [{"path": "search.js", "line": 1, "quote": quote}]}],
                       "confidence": "high"})


def labels(prepared, tmp_path):
    case = json.loads((prepared / "cases.jsonl").read_text())
    gold = tmp_path / "private-gold.jsonl"
    gold.write_text(json.dumps({"case_id": case["case_id"], "expected_verdict": "confirmed",
                                "rationale": "verified separately", "verified_security": True, "runtime": "verified"}))
    receipt = tmp_path / "labels.json"
    write_json(receipt, {"reviewer": "tester", "prepared_sha256": verify_seal(prepared, "prepared.json")["sha256"],
                        "gold_sha256": hashlib.sha256(gold.read_bytes()).hexdigest()})
    return gold, receipt


def test_discovery_provenance_and_rejections(pilot, tmp_path):
    source, profile = pilot
    candidate = {"title": "SQL injection", "rationale": "input in query", "cwe": ["CWE-89"],
                 "severity": "high", "citations": [{"path": "search.js", "line": 1, "quote": "db.query(req.query.q)"}],
                 "uncertainty": "depends on db API"}
    bad = {**candidate, "citations": [{"path": "search.js", "line": 1, "quote": "invented quote"}]}
    client = AuditedClient([json.dumps({"candidates": [candidate, bad]})])
    out = tmp_path / "discovery"
    result = discover(source, profile, out, client)
    assert result["accepted"] == 1 and result["rejected"] == 1
    f = Finding.model_validate_json((out / "findings.jsonl").read_text())
    assert f.source_tool == "llm-discovery" and f.source_finding_id_synthesized
    assert f.raw_evidence_ref.endswith("#/candidates/0")
    assert "GOLD SECRET" not in client.prompts[0][1]
    assert "planting-ledger.md" not in client.prompts[0][1]
    assert json.loads((out / "rejected.json").read_text())[0]["human_adjudication"] == "pending"


def test_redaction_and_bounds(pilot, tmp_path):
    source, profile = pilot
    (source / "search.js").write_text('const token = "supersecret"\n')
    _, contents, _ = freeze_source(source, profile, tmp_path / "frozen")
    assert "supersecret" not in contents["search.js"] and "[REDACTED]" in contents["search.js"]
    with pytest.raises(ValueError, match="no silent truncation"):
        freeze_source(source, profile, tmp_path / "too-big", max_bytes=5)
    assert "real-secret" not in redact("CF-Access-Client-Secret: real-secret\nCF-Access-Client-ID: real-secret")


def test_duplicate_origins_and_gold_exclusion(pilot, tmp_path):
    prepared = prep(pilot, tmp_path, [finding("s1"), finding("s2", "other")])
    packet = json.loads((prepared / "cases.jsonl").read_text())
    assert len(packet["original_findings"]) == 2
    assert "gold" not in packet["prompt"].lower()
    assert len(packet["evidence"]) == 4


def test_one_response_reused_all_arms_and_smoke(pilot, tmp_path):
    prepared = prep(pilot, tmp_path)
    gold, receipt = labels(prepared, tmp_path)
    client = AuditedClient([response()])
    smoke = tmp_path / "smoke"
    assert run_cases(prepared, smoke, smoke=True, labels_receipt=receipt, client=client)["processing_failures"] == 0
    assert len(client.prompts) == 1
    batch_client = AuditedClient([])
    batch = tmp_path / "batch"
    run_cases(prepared, batch, smoke_run=smoke, labels_receipt=receipt, client=batch_client)
    assert len(batch_client.prompts) == 0
    row = json.loads((batch / "results.jsonl").read_text())
    assert (row["rules_only"], row["llm_only"], row["hybrid"]) == ("needs_review", "likely", "likely")
    result = score_cases(prepared, batch, gold)
    assert result["arms"]["hybrid"]["relaxed_agreement"] == 1
    assert result["arms"]["hybrid"]["exact_agreement"] == 0
    assert result["human_metrics"]["unsupported_reasoning"] == "unmeasured"
    assert "%" not in (batch / "score.md").read_text()


def test_failed_citation_changes_hybrid_only(pilot, tmp_path):
    prepared = prep(pilot, tmp_path)
    _, receipt = labels(prepared, tmp_path)
    out = tmp_path / "run"
    run_cases(prepared, out, smoke=True, labels_receipt=receipt, client=AuditedClient([response("invented quote")]))
    row = json.loads((out / "results.jsonl").read_text())
    assert row["llm_only"] == "likely" and row["hybrid"] == "needs_review"
    assert row["dropped_claims"][0]["_why"] == "no citation verified"


@pytest.mark.parametrize("raw", [{}, {"claims": "bad", "confidence": "high"}, {"claims": [None], "confidence": "high"}])
def test_malformed_response(raw):
    with pytest.raises(ValueError):
        raw_verdict(raw)


@pytest.mark.parametrize("stances,expected", [(["refutes"], "not_applicable"), (["non_security"], "valid_non_security"),
                                            (["supports", "refutes"], "needs_review"), ([], "needs_review")])
def test_raw_aggregation(stances, expected):
    raw = {"claims": [{"statement": "claim", "stance": s, "citations": []} for s in stances], "confidence": "low"}
    assert raw_verdict(raw) == expected


def test_freeze_and_model_gates(pilot, tmp_path):
    prepared = prep(pilot, tmp_path)
    _, receipt = labels(prepared, tmp_path)
    with pytest.raises(ValueError, match="smoke"):
        run_cases(prepared, tmp_path / "batch", client=AuditedClient([]), labels_receipt=receipt)
    client = AuditedClient([response()])
    client.last_reported_model = "wrong"
    out = tmp_path / "wrong"
    assert run_cases(prepared, out, smoke=True, client=client, labels_receipt=receipt)["processing_failures"] == 1
    assert not (out / "smoke.json").exists()
    assert (out / "case-0000" / "response.txt").exists()
    (prepared / "source" / "search.js").write_text("changed")
    with pytest.raises(ValueError, match="frozen artifact"):
        verify_seal(prepared, "prepared.json")


def test_empty_denominators(pilot, tmp_path):
    prepared = prep(pilot, tmp_path)
    (prepared / "cases.jsonl").write_text("")
    from fva.evaluation import seal
    seal(prepared, "prepared.json", [p for p in prepared.rglob("*") if p.is_file() and p.name != "prepared.json"])
    out = tmp_path / "empty"
    run_cases(prepared, out, client=AuditedClient([]))
    gold = tmp_path / "gold.jsonl"
    gold.write_text("")
    assert score_cases(prepared, out, gold)["arms"]["hybrid"]["denominator"] == 0


def test_audited_cli_schema_and_tools(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: name)
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    seen = {}
    def fake(argv, **kw):
        seen["argv"] = argv
        out = argv[argv.index("--output-last-message") + 1]
        from pathlib import Path
        Path(out).write_text(response())
        events = [{"type": "turn.started"}, {"type": "item.completed", "item": {"type": "command_execution"}},
                  {"type": "turn.completed", "usage": {"output_tokens": 5}}]
        return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(e) for e in events), "model: gpt-6.1-sol\n")
    monkeypatch.setattr(subprocess, "run", fake)
    client = CodexCliClient(model=FIXED_MODEL, schema_file=schema, audit=True)
    client.complete("sys", "prompt")
    assert "--ignore-user-config" in seen["argv"] and "--json" in seen["argv"]
    assert seen["argv"][seen["argv"].index("--output-schema") + 1] == str(schema)
    assert client.last_audit["tool_items"] == ["command_execution"]
    assert client.last_reported_model == FIXED_MODEL


def test_link_approval_hashes_and_observation(pilot, tmp_path):
    source, profile = pilot
    static = finding()
    dast = Finding(finding_id="d1", run_id="r", source_tool="polaris", source_finding_id="d1",
                   rule_id="dast.sqli", title="SQL injection", description="scanner observed SQL error",
                   severity="high", finding_type="dast", cwe=("CWE-89",),
                   endpoint={"method": "GET", "path": "/search", "parameter": "q", "parameter_location": "query"},
                   scanner_metadata={"request_snippet": "CF-Access-Client-Secret: real-secret\nGET /search?q=x"},
                   raw_evidence_ref="raw:sha256:" + "1" * 64)
    canonical = tmp_path / "canonical.jsonl"
    canonical.write_text(static.model_dump_json() + "\n" + dast.model_dump_json() + "\n")
    expected = tmp_path / "expected.json"
    write_json(expected, [{"method": "GET", "path": "/search", "handlers": ["search.js"]}])
    first = tmp_path / "first"
    report = preflight(source, profile, first, expected_routes=expected)
    prepare_cases(source, profile, first, report, canonical_paths=[canonical])
    packet = json.loads((first / "cases.jsonl").read_text())
    assert packet["approved_link_ids"] == []
    assert all(e["evidence_type"] != "dast_observation" for e in packet["evidence"])
    template = json.loads((first / "approval-template.json").read_text())
    assert len(template["links"]) == 1
    template["links"][0].update(decision="approved", reviewer="human", rationale="route, handler, q, CWE and SQL error match")
    approval = tmp_path / "approval.json"
    write_json(approval, template)
    second = tmp_path / "second"
    report = preflight(source, profile, second, expected_routes=expected)
    prepare_cases(source, profile, second, report, canonical_paths=[canonical], approved=approval)
    packet = json.loads((second / "cases.jsonl").read_text())
    assert packet["approved_link_ids"]
    assert "real-secret" not in packet["prompt"]
    ev = next(e for e in packet["evidence"] if e["evidence_type"] == "dast_observation")
    assert "scanner observed SQL error" in ev["summary"]
    assert all(e["evidence_type"] != "human_review" for e in packet["evidence"])
    template["scope"]["source_sha256"] = "wrong"
    write_json(approval, template)
    with pytest.raises(ValueError, match="scope mismatch"):
        prepare_cases(source, profile, tmp_path / "third", report, canonical_paths=[canonical], approved=approval)


def test_explicit_gold_format_and_legacy(tmp_path):
    from fva.export.score import load_key
    path = tmp_path / "gold.jsonl"
    # Use an actual legacy vocabulary entry rather than a new alias.
    from fva import reason_codes
    legacy = next(iter(reason_codes.LEGACY_POC_MAP))
    path.write_text(json.dumps({"case_id": "c", "expected_verdict": "likely", "rationale": "source checked"}) + "\n" +
                    json.dumps({"candidate_id": "p", "classification": legacy}))
    assert set(load_key(path)) == {"c", "p"}
