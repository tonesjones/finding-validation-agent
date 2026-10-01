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
    evs = [_ev("e1", "l", EvidenceType.model_assessment, Stance.supports),
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
    assert rows["POL-t"]["suggested_severity"] == "informational"
    assert rows["POL-l"]["fva_verdict"] == "likely"
    assert rows["POL-m"]["fva_verdict"] == "needs_review"  # model output alone is never likely
    assert rows["POL-d"]["fva_verdict"] == "confirmed" and rows["POL-d"]["reason_codes"] == "DAST_OBSERVED"
    assert rows["POL-q"]["fva_verdict"] == "valid_non_security"
    assert (run / "worksheet.html").read_text().startswith("<!doctype html>")


def _fill(run, decisions):
    worksheet.write(run)
    with open(run / "worksheet.csv", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        if r["source_finding_id"] in decisions:
            r["reviewer_decision"], r["reviewer"] = decisions[r["source_finding_id"]], "Ana"
    out = run / "filled.csv"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=worksheet.COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return out


def test_review_confirms_likely_and_scores_agreement(run):
    s = worksheet.import_reviews(run, _fill(run, {"POL-l": "confirmed", "POL-t": "agree"}))
    assert s["reviewed"] == 2 and s["agreement"] == {"likely": "0/1", "not_applicable": "1/1"}
    rev = {json.loads(l)["source_finding_id"]: json.loads(l) for l in (run / "reviews.jsonl").read_text().splitlines()}
    v = rev["POL-l"]["verdict"]
    assert v["verdict"] == "confirmed" and v["reason_codes"] == ["REVIEWER_CONFIRMED"]
    assert v["supersedes"] == "suggestion:l" and rev["POL-l"]["evidence"]["evidence_type"] == "human_review"


def test_review_needs_reviewer_and_valid_decision(run):
    p = _fill(run, {"POL-l": "maybe"})
    with pytest.raises(ValueError, match="reviewer_decision"):
        worksheet.import_reviews(run, p)
