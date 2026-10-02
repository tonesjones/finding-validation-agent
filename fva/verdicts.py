"""Suggested verdict per finding from a run's evidence (rules only; pre-v0.6 verdict reasoner).

Every suggestion that closes or promotes a finding, rule-decided closures included, passes
`fva.invariants.check_verdict` on the evidence it cites; anything that would not falls back to needs_review.
Used by the worksheet and by scoring.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fva.invariants import InvariantError, check_verdict
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue as V

# pipeline skip disposition -> not_applicable reason code (decided before any model call)
SKIP_CODES = {
    "surface:test": "TEST_ONLY", "surface:fixture": "NON_EXECUTABLE_FIXTURE",
    "surface:infrastructure": "UNUSED_DEPLOYMENT_CONFIG", "surface:api_spec": "DOCUMENTATION_ONLY",
    "surface:documentation": "DOCUMENTATION_ONLY", "dependency:version_drift": "VERSION_DRIFT",
    "dependency:not_installed": "VERSION_DRIFT",
}
RULE_CONTEXT = {EvidenceType.static_source, EvidenceType.reachability, EvidenceType.dependency_resolution}


def check_suggestion(fid: str, verdict: V, codes: tuple[str, ...], evs: list[EvidenceRecord], conf: str) -> bool:
    if not evs:  # a verdict must cite evidence
        return False
    # some records (e.g. source location) carry no profile id
    profile = next((e.deployment_profile_id for e in evs if e.deployment_profile_id), "worksheet")
    try:
        check_verdict(Verdict(verdict_id="probe", finding_id=fid, deployment_profile_id=profile,
                              verdict=verdict, reason_codes=codes, confidence=conf,
                              evidence_ids=tuple(e.evidence_id for e in evs), narrative="-",
                              decided_at=datetime.now(timezone.utc), decided_by={"method": "rules"}),
                      {e.evidence_id: e for e in evs})
        return True
    except InvariantError:
        return False


def suggest_verdict(row: dict, evs: list[EvidenceRecord]) -> tuple[V, tuple[str, ...], str, list[EvidenceRecord]]:
    """(verdict, reason codes, confidence, cited evidence) for one finding."""
    disp = row["disposition"]
    if disp in SKIP_CODES:  # deployment-boundary / dependency rules: decided before any model call
        code = (SKIP_CODES[disp],)
        if check_suggestion(row["finding_id"], V.not_applicable, code, evs, "high"):
            return V.not_applicable, code, "high", evs
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs  # e.g. a run made before rule evidence
    if disp.startswith(("surface:", "dependency:", "reachability:")):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    stances = {e.stance for e in evs}
    dast = [e for e in evs if e.evidence_type is EvidenceType.dast_observation and e.stance is Stance.supports]
    if dast and Stance.refutes not in stances:
        return V.confirmed, ("DAST_OBSERVED",), "high", evs
    if Stance.supports in stances and Stance.refutes in stances:
        return V.needs_review, ("CONFLICTING_EVIDENCE",), "medium", evs
    if Stance.non_security in stances and Stance.supports not in stances:
        if check_suggestion(row["finding_id"], V.valid_non_security, ("QUALITY_NOT_SECURITY",), evs, "medium"):
            return V.valid_non_security, ("QUALITY_NOT_SECURITY",), "medium", evs
    if Stance.supports in stances:
        code = "VULNERABLE_VERSION_IMPORTED" if row["finding_type"] == "sca" else "STATIC_REACHABLE_SINK"
        if any(e.evidence_type in RULE_CONTEXT for e in evs) and check_suggestion(row["finding_id"], V.likely,
                                                                                  (code,), evs, "medium"):
            return V.likely, (code,), "medium", evs
    # A model refutation alone stays needs_review here: which not_applicable reason applies is a reviewer call.
    return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
