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
    control = ev("c", Stance.neutral, et=EvidenceType.negative_control).model_copy(
        update={"tool_versions": {"control_for": "e1"}})
    check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1", "c")),
                  {"e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe), "c": control})


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
    control = ev("c", Stance.neutral, fids=("f1", "f2", "f3"), et=EvidenceType.negative_control).model_copy(
        update={"tool_versions": {"control_for": "e1"}})
    check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1", "c")), {"e1": e, "c": control})


@pytest.mark.parametrize("control_for", [None, "other-probe"])
def test_runtime_confirmation_requires_its_control(control_for):
    evidence = {"e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe)}
    if control_for:
        evidence["c"] = ev("c", Stance.neutral, et=EvidenceType.negative_control).model_copy(
            update={"tool_versions": {"control_for": control_for}})
    with pytest.raises(InvariantError, match="negative control"):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), tuple(evidence)), evidence)


def test_runtime_confirmation_rejects_cross_deployment_control():
    evidence = {
        "e1": ev("e1", Stance.supports, et=EvidenceType.runtime_probe),
        "c": ev("c", Stance.neutral, et=EvidenceType.negative_control).model_copy(
            update={"deployment_profile_id": "other", "tool_versions": {"control_for": "e1"}}),
    }
    with pytest.raises(InvariantError, match="deployment profile"):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("e1", "c")), evidence)


def test_negative_control_alone_cannot_confirm():
    with pytest.raises(InvariantError, match="requires supporting"):
        check_verdict(vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("c",)),
                      {"c": ev("c", Stance.supports, et=EvidenceType.negative_control)})


def test_historical_import_does_not_claim_new_probe_controls():
    v = vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("i",)).model_copy(
        update={"decided_by": {"method": "import"}})
    check_verdict(v, {"i": ev("i", Stance.supports, et=EvidenceType.imported_assessment)})


def test_imported_record_cannot_bypass_new_probe_control():
    v = vd(VerdictValue.confirmed, ("RUNTIME_CONFIRMED",), ("p", "i")).model_copy(
        update={"decided_by": {"method": "import"}})
    with pytest.raises(InvariantError, match="negative control"):
        check_verdict(v, {"p": ev("p", Stance.supports, et=EvidenceType.runtime_probe),
                          "i": ev("i", Stance.supports, et=EvidenceType.imported_assessment)})


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
