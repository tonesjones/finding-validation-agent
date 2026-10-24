"""`likely` reason codes claim import or reachability, so a rule must have shown it."""
from datetime import datetime, timezone

import pytest

from fva.schemas import EvidenceRecord, EvidenceType, Stance
from fva.verdicts import suggest_verdict

NOW = datetime(2026, 10, 23, tzinfo=timezone.utc)


def _ev(eid, et, method, stance):
    return EvidenceRecord(evidence_id=eid, finding_ids=("f",), evidence_type=et, method=method, stance=stance,
                          summary="s", collected_at=NOW, deployment_profile_id="p")


def _suggest(ftype, reach_status):
    row = {"finding_id": "f", "disposition": "assess", "finding_type": ftype, "deployment_profile_id": "p"}
    evs = [_ev("r", EvidenceType.reachability, f"static_import_graph:{reach_status}", Stance.neutral),
           _ev("m", EvidenceType.model_assessment, "model", Stance.supports)]
    verdict, codes, _, _ = suggest_verdict(row, evs)
    return verdict.value, codes


@pytest.mark.parametrize("ftype,status", [
    ("sca", "not_imported_directly"), ("sca", "declared_not_imported"), ("sca", "unknown"),
    ("sast", "not_code"), ("sast", "not_in_entrypoint_graph"), ("sast", "unknown")])
def test_model_support_without_shown_reach_stays_open(ftype, status):
    assert _suggest(ftype, status) == ("needs_review", ("INSUFFICIENT_EVIDENCE",))


@pytest.mark.parametrize("ftype,status,code", [
    ("sca", "imported_by_reachable_code", "VULNERABLE_VERSION_IMPORTED"),
    ("sca", "imported_by_shipped_code", "VULNERABLE_VERSION_IMPORTED"),
    ("sast", "in_entrypoint_graph", "STATIC_REACHABLE_SINK")])
def test_model_support_with_shown_reach_is_likely(ftype, status, code):
    assert _suggest(ftype, status) == ("likely", (code,))


def test_sast_reach_does_not_count_for_sca():
    assert _suggest("sca", "in_entrypoint_graph") == ("needs_review", ("INSUFFICIENT_EVIDENCE",))
