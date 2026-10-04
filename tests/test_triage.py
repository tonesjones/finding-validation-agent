import json
from datetime import datetime, timezone

import pytest

from fva import reason_codes, triage
from fva.schemas import EvidenceRecord, EvidenceType as T, Stance as S, VerdictValue as V
from fva.verdicts import check_suggestion

NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def _ev(eid, et, stance, profile="p", fid="f"):
    return EvidenceRecord(evidence_id=eid, finding_ids=(fid,), evidence_type=et, method="m", stance=stance,
                          summary="s", collected_at=NOW, deployment_profile_id=profile)


def _route(verdict, codes, conf, evs, sev="high", profile="p", verified=frozenset()):
    return triage.route("f", sev, verdict, codes, conf, evs, profile=profile, verified_runtime_ids=verified)


def test_exception_codes_are_needs_review_vocabulary():
    assert all(reason_codes.verdict_for(c) is V.needs_review for c in triage.EXCEPTIONS)


def test_rule_backed_likely_routes_auto():
    evs = [_ev("r", T.reachability, S.neutral), _ev("m", T.model_assessment, S.supports)]
    assert _route(V.likely, ("STATIC_REACHABLE_SINK",), "medium", evs) == ("auto", ())


def test_high_confidence_rule_closure_routes_auto_at_any_severity():
    evs = [_ev("b", T.deployment_boundary, S.refutes)]
    assert _route(V.not_applicable, ("TEST_ONLY",), "high", evs, sev="critical") == ("auto", ())


def test_low_confidence():
    evs = [_ev("r", T.reachability, S.neutral), _ev("m", T.model_assessment, S.supports)]
    assert _route(V.likely, ("STATIC_REACHABLE_SINK",), "low", evs) == ("review", ("LOW_CONFIDENCE",))


def test_conflicting_evidence():
    evs = [_ev("r", T.reachability, S.supports), _ev("d", T.dependency_resolution, S.refutes)]
    assert _route(V.needs_review, ("CONFLICTING_EVIDENCE",), "medium", evs) == ("review", ("CONFLICTING_EVIDENCE",))


def test_model_only_refutation():
    evs = [_ev("r", T.reachability, S.neutral), _ev("m", T.model_assessment, S.refutes)]
    assert _route(V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs) == ("review", ("MODEL_ONLY_REFUTATION",))


def test_model_only_non_security_demotion_goes_to_review_even_when_low_severity():
    evs = [_ev("s", T.static_source, S.neutral, profile=None), _ev("m", T.model_assessment, S.non_security)]
    assert check_suggestion("f", V.valid_non_security, ("QUALITY_NOT_SECURITY",), evs, "medium", "p")
    assert _route(V.valid_non_security, ("QUALITY_NOT_SECURITY",), "medium", evs, sev="low") == (
        "review", ("MODEL_ONLY_REFUTATION",))


def test_profile_mismatch():
    evs = [_ev("b", T.deployment_boundary, S.refutes, profile="other")]
    assert _route(V.not_applicable, ("TEST_ONLY",), "high", evs) == ("review", ("PROFILE_MISMATCH",))


def test_missing_profile_with_runtime_evidence():
    evs = [_ev("x", T.dast_observation, S.supports)]
    assert "PROFILE_MISMATCH" in _route(V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs, profile=None)[1]


def test_unverified_runtime():
    evs = [_ev("p1", T.runtime_probe, S.supports), _ev("r", T.reachability, S.neutral)]
    assert _route(V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs) == ("review", ("UNVERIFIED_RUNTIME",))
    assert "UNVERIFIED_RUNTIME" not in _route(V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs,
                                              verified=frozenset({"p1"}))[1]


@pytest.mark.parametrize("sev,expected", [("high", ("review", ("HIGH_IMPACT_CLOSURE",))),
                                          ("critical", ("review", ("HIGH_IMPACT_CLOSURE",))),
                                          ("medium", ("auto", ()))])
def test_high_impact_closure_below_high_confidence(sev, expected):
    evs = [_ev("d", T.dependency_resolution, S.refutes)]
    assert _route(V.not_applicable, ("ADVISORY_PRECONDITION_ABSENT",), "medium", evs, sev=sev) == expected


def test_needs_review_without_specific_exception():
    evs = [_ev("r", T.reachability, S.neutral)]
    assert _route(V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs) == ("review", ("INSUFFICIENT_EVIDENCE",))


def test_suggestion_failing_invariants_never_routes_auto():
    evs = [_ev("m", T.model_assessment, S.supports)]  # likely from model output alone breaks the invariants
    assert _route(V.likely, ("STATIC_REACHABLE_SINK",), "medium", evs) == ("review", ("INSUFFICIENT_EVIDENCE",))


def _row(fid, disp, sev="high"):
    return {"finding_id": fid, "source_finding_id": f"POL-{fid}", "source_tool": "polaris", "finding_type": "sast",
            "title": "t", "severity": sev, "cwe": ["CWE-89"], "path": "a.ts", "line": 1, "package": None,
            "endpoint": None, "disposition": disp, "issue_id": f"i-{fid}", "primary": True}


def test_build_auto_rows_pass_invariants(tmp_path):
    rows = [_row("t", "surface:test"), _row("l", "assess"), _row("m", "assess"), _row("q", "assess", "low")]
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p"}))
    evs = [_ev("e0", T.deployment_boundary, S.refutes, fid="t"),
           _ev("e1", T.model_assessment, S.supports, fid="l"), _ev("e2", T.reachability, S.neutral, fid="l"),
           _ev("e3", T.model_assessment, S.refutes, fid="m"),
           _ev("e4", T.model_assessment, S.non_security, fid="q")]
    (tmp_path / "evidence.jsonl").write_text("\n".join(e.model_dump_json() for e in evs) + "\n")
    out = {r["source_finding_id"]: r for r in triage.build(tmp_path)}
    assert {k: (r["route"], r["exceptions"]) for k, r in out.items()} == {
        "POL-t": ("auto", []), "POL-l": ("auto", []), "POL-m": ("review", ["MODEL_ONLY_REFUTATION"]),
        "POL-q": ("review", ["MODEL_ONLY_REFUTATION"])}
    by_id = {e.evidence_id: e for e in evs}
    for r in out.values():
        if r["route"] == "auto":
            assert check_suggestion(r["finding_id"], V(r["verdict"]), tuple(r["reason_codes"]),
                                    [by_id[i] for i in r["evidence_ids"]], r["confidence"], "p")
