import csv
import json
from datetime import datetime, timezone

import pytest

from fva.export import worksheet
from fva.schemas import EvidenceRecord, EvidenceType, Stance

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _ev(eid, fid, et, stance, profile="p"):
    return EvidenceRecord(evidence_id=eid, finding_ids=(fid,), evidence_type=et, method="m", stance=stance,
                          summary="s", collected_at=NOW, deployment_profile_id=profile).model_dump_json()


def _row(fid, ftype, disp, sev="high"):
    return {"finding_id": fid, "source_finding_id": f"POL-{fid}", "source_tool": "polaris", "finding_type": ftype,
            "title": "t", "severity": sev, "cwe": ["CWE-89"], "path": "a.ts", "line": 1, "package": None,
            "endpoint": None, "disposition": disp, "issue_id": f"i-{fid}", "primary": True}


@pytest.fixture
def run(tmp_path):
    rows = [_row("t", "sast", "surface:test"), _row("l", "sast", "assess"), _row("m", "sast", "assess"),
            _row("d", "sast", "assess"), _row("q", "sast", "assess", "low")]
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p"}))
    evs = [_ev("e0", "t", EvidenceType.deployment_boundary, Stance.refutes),  # rule skip cites its boundary record
           _ev("e1", "l", EvidenceType.model_assessment, Stance.supports),
           _ev("e2", "l", EvidenceType.reachability, Stance.neutral),
           _ev("e3", "m", EvidenceType.model_assessment, Stance.supports),  # model only
           _ev("e4", "d", EvidenceType.dast_observation, Stance.supports),
           _ev("e6", "q", EvidenceType.static_source, Stance.neutral, profile=None),  # real runs: no profile id
           _ev("e5", "q", EvidenceType.model_assessment, Stance.non_security)]
    (tmp_path / "evidence.jsonl").write_text("\n".join(evs) + "\n")
    return tmp_path


def test_suggestions(run):
    s = worksheet.write(run)
    rows = {r["source_finding_id"]: r for r in csv.DictReader(open(run / "worksheet.csv", encoding="utf-8-sig"))}
    assert s["rows"] == 5 and list(rows) and set(rows) == {"POL-t", "POL-l", "POL-m", "POL-d", "POL-q"}
    assert rows["POL-t"]["fva_verdict"] == "not_applicable" and rows["POL-t"]["reason_codes"] == "TEST_ONLY"
    assert rows["POL-t"]["suggested_severity"] == "informational" and rows["POL-t"]["evidence_ids"] == "e0"
    assert rows["POL-l"]["fva_verdict"] == "likely"
    assert rows["POL-m"]["fva_verdict"] == "needs_review"  # model output alone is never likely
    assert rows["POL-d"]["fva_verdict"] == "confirmed" and rows["POL-d"]["reason_codes"] == "DAST_OBSERVED"
    assert rows["POL-q"]["fva_verdict"] == "valid_non_security"
    assert (run / "worksheet.html").read_text().startswith("<!doctype html>")


def test_rule_skip_without_evidence_stays_open(run):
    """A run made before rule evidence existed: the closure has nothing to cite, so it is not closed."""
    ev = run / "evidence.jsonl"
    ev.write_text("\n".join(l for l in ev.read_text().splitlines() if '"e0"' not in l) + "\n")
    s = worksheet.write(run)
    rows = {r["source_finding_id"]: r for r in csv.DictReader(open(run / "worksheet.csv", encoding="utf-8-sig"))}
    assert rows["POL-t"]["fva_verdict"] == "needs_review" and rows["POL-t"]["evidence_ids"] == ""
    assert "1 rule-skipped" in s["warning"]


def test_agent_authored_runtime_and_precondition_records_stay_open(tmp_path):
    rows = [_row("runtime", "sast", "assess"), _row("absent", "sca", "assess"),
            _row("model", "sca", "assess"), _row("conflict", "sca", "assess")]
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    evs = [_ev("probe", "runtime", EvidenceType.runtime_probe, Stance.supports),
           _ev("precondition", "absent", EvidenceType.advisory_precondition, Stance.refutes),
           _ev("claim", "model", EvidenceType.model_assessment, Stance.refutes),
           _ev("absent-conflict", "conflict", EvidenceType.advisory_precondition, Stance.refutes),
           _ev("probe-conflict", "conflict", EvidenceType.runtime_probe, Stance.supports)]
    (tmp_path / "evidence.jsonl").write_text("\n".join(evs) + "\n")
    worksheet.write(tmp_path)
    with open(tmp_path / "worksheet.csv", encoding="utf-8-sig") as fh:
        actual = {r["source_finding_id"]: (r["fva_verdict"], r["reason_codes"]) for r in csv.DictReader(fh)}
    assert actual == {
        "POL-runtime": ("needs_review", "INSUFFICIENT_EVIDENCE"),
        "POL-absent": ("needs_review", "INSUFFICIENT_EVIDENCE"),
        "POL-model": ("needs_review", "INSUFFICIENT_EVIDENCE"),
        "POL-conflict": ("needs_review", "INSUFFICIENT_EVIDENCE"),
    }


@pytest.mark.parametrize("ftype", ["sast", "sca"])
def test_precondition_refutation_does_not_close_any_finding(tmp_path, ftype):
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p"}))
    (tmp_path / "findings.jsonl").write_text(json.dumps(_row("f", ftype, "assess")) + "\n")
    (tmp_path / "evidence.jsonl").write_text(_ev("e", "f", EvidenceType.advisory_precondition, Stance.refutes))
    assert worksheet.build(tmp_path)[0]["fva_verdict"] == "needs_review"


@pytest.mark.parametrize("etype", [EvidenceType.runtime_probe, EvidenceType.dast_observation])
@pytest.mark.parametrize("profile", ["local", None])
def test_run_profile_is_not_inferred_from_probe(tmp_path, etype, profile):
    if profile:
        (tmp_path / "summary.json").write_text(json.dumps({"profile": "hosted"}))
    row = _row("f", "sast", "assess")
    row["deployment_profile_id"] = "local"  # cannot override the run's profile
    (tmp_path / "findings.jsonl").write_text(json.dumps(row) + "\n")
    (tmp_path / "evidence.jsonl").write_text(_ev("e", "f", etype, Stance.supports, profile="local"))
    assert worksheet.build(tmp_path)[0]["fva_verdict"] == "needs_review"


def test_unknown_probe_with_matching_profile_and_control_stays_open(tmp_path):
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p"}))
    (tmp_path / "findings.jsonl").write_text(json.dumps(_row("f", "sast", "assess")) + "\n")
    control = json.loads(_ev("control", "f", EvidenceType.negative_control, Stance.neutral))
    control["tool_versions"] = {"control_for": "probe"}
    (tmp_path / "evidence.jsonl").write_text(
        _ev("probe", "f", EvidenceType.runtime_probe, Stance.supports) + "\n" + json.dumps(control))
    assert worksheet.build(tmp_path)[0]["fva_verdict"] == "needs_review"


def test_check_suggestion_requires_expected_runtime_profile():
    from fva.verdicts import check_suggestion
    from fva.schemas import VerdictValue

    evidence = EvidenceRecord.model_validate_json(
        _ev("e", "f", EvidenceType.dast_observation, Stance.supports))
    assert not check_suggestion("f", VerdictValue.confirmed, ("DAST_OBSERVED",), [evidence], "high")
    assert not check_suggestion("f", VerdictValue.confirmed, ("DAST_OBSERVED",), [evidence], "high", "other")
    assert check_suggestion("f", VerdictValue.confirmed, ("DAST_OBSERVED",), [evidence], "high", "p")
