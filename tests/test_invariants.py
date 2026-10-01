from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from fva.invariants import InvariantError, check_verdict
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def ev(eid, stance, fids=("f1",), et=EvidenceType.static_source):
    return EvidenceRecord(evidence_id=eid, finding_ids=fids, evidence_type=et, method="m",
                          stance=stance, summary="s", collected_at=NOW,
                          deployment_profile_id="p")


def vd(verdict, codes, eids):
    return Verdict(verdict_id="v", finding_id="f1", deployment_profile_id="p", verdict=verdict,
                   reason_codes=codes, confidence="high", evidence_ids=eids, narrative="n",
                   decided_at=NOW, decided_by={"method": "rules"})


def test_confirmed_ok():
    check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1",)),
                  {"e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe)})


@pytest.mark.parametrize("et", [EvidenceType.static_source, EvidenceType.reachability, EvidenceType.model_assessment])
def test_static_or_model_support_cannot_confirm(et):
    with pytest.raises(InvariantError, match="runtime"):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1",)), {"e1": ev("e1", Stance.supports, et=et)})


def test_confirmed_needs_supporting_evidence():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1",)), {"e1": ev("e1", Stance.neutral)})


def test_conflict_forces_needs_review():
    e = {"e1": ev("e1", Stance.supports), "e2": ev("e2", Stance.refutes)}
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.not_applicable, ("TEST_ONLY",), ("e1", "e2")), e)
    check_verdict(vd(VerdictValue.needs_review, ("CONFLICTING_EVIDENCE",), ("e1", "e2")), e)


def test_reason_code_must_match_verdict():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.confirmed, ("TEST_ONLY",), ("e1",)),
                      {"e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe)})


def test_unknown_reason_code():
    with pytest.raises(ValueError):
        check_verdict(vd(VerdictValue.confirmed, ("MADE_UP",), ("e1",)), {"e1": ev("e1", Stance.supports)})


def test_evidence_must_cover_finding():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1",)),
                      {"e1": ev("e1", Stance.supports, fids=("other",), et=EvidenceType.runtime_probe)})


def test_verdict_needs_evidence():
    with pytest.raises(ValidationError):
        vd(VerdictValue.needs_review, ("INSUFFICIENT_EVIDENCE",), ())


def test_runtime_evidence_needs_profile():
    with pytest.raises(ValidationError):
        EvidenceRecord(evidence_id="e", finding_ids=("f1",), evidence_type=EvidenceType.runtime_probe,
                       method="http_probe", stance=Stance.supports, summary="s", collected_at=NOW)


def test_one_probe_many_findings():
    e = ev("e1", Stance.supports, fids=("f1", "f2", "f3"), et=EvidenceType.runtime_probe)
    check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1",)), {"e1": e})


# ------------------------------------------------------------------ likely (static-only customers, no DAST)

def test_likely_ok_with_model_support_and_rule_context():
    check_verdict(vd(VerdictValue.likely, ("STATIC_REACHABLE_SINK",), ("e1", "e2")),
                  {"e1": ev("e1", Stance.supports, et=EvidenceType.model_assessment),
                   "e2": ev("e2", Stance.neutral, et=EvidenceType.reachability)})


def test_likely_ok_with_rule_support_alone():
    check_verdict(vd(VerdictValue.likely, ("VULNERABLE_VERSION_IMPORTED",), ("e1",)),
                  {"e1": ev("e1", Stance.supports, et=EvidenceType.dependency_resolution)})


def test_model_alone_cannot_make_likely():
    with pytest.raises(InvariantError, match="model output alone"):
        check_verdict(vd(VerdictValue.likely, ("STATIC_REACHABLE_SINK",), ("e1",)),
                      {"e1": ev("e1", Stance.supports, et=EvidenceType.model_assessment)})


def test_likely_needs_support():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.likely, ("STATIC_REACHABLE_SINK",), ("e1",)),
                      {"e1": ev("e1", Stance.neutral, et=EvidenceType.reachability)})


def test_likely_conflict_forces_needs_review():
    with pytest.raises(InvariantError, match="needs_review"):
        check_verdict(vd(VerdictValue.likely, ("STATIC_REACHABLE_SINK",), ("e1", "e2")),
                      {"e1": ev("e1", Stance.supports, et=EvidenceType.static_source),
                       "e2": ev("e2", Stance.refutes, et=EvidenceType.model_assessment)})


def test_likely_codes_cannot_confirm():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.confirmed, ("STATIC_REACHABLE_SINK",), ("e1",)),
                      {"e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe)})
