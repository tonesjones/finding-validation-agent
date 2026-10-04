"""Suggested verdict per finding from a run's evidence (rules only; pre-v0.6 verdict reasoner).

Every suggestion that closes or promotes a finding, rule-decided closures included, passes
`fva.invariants.check_verdict` on the evidence it cites; anything that would not falls back to needs_review.
Used by the worksheet and by scoring.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fva.correlation.quality import QUALITY_CHECKERS
from fva.invariants import InvariantError, check_verdict
from fva.reason_codes import verdict_for
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue as V

# pipeline skip disposition -> closing reason code (decided before any model call)
SKIP_CODES = {
    "surface:test": "TEST_ONLY", "surface:fixture": "NON_EXECUTABLE_FIXTURE",
    "surface:infrastructure": "UNUSED_DEPLOYMENT_CONFIG", "surface:api_spec": "DOCUMENTATION_ONLY",
    "surface:documentation": "DOCUMENTATION_ONLY", "dependency:version_drift": "VERSION_DRIFT",
    "dependency:not_installed": "VERSION_DRIFT",
    "dependency:advisory_version_unaffected": "ADVISORY_VERSION_MISMATCH",
    "dependency:vulnerable_function_not_called": "VULNERABLE_FUNCTION_NOT_CALLED",
    "dependency:advisory_precondition_absent": "ADVISORY_PRECONDITION_ABSENT",
    **{f"quality:{name}": "QUALITY_NOT_SECURITY" for name in QUALITY_CHECKERS},
}
# Rule closures that can miss a use the source scan cannot see stay below high confidence.
# A quality checker can flag a mistyped security check, so its closure also stays below high.
SKIP_CONFIDENCE = {"dependency:vulnerable_function_not_called": "medium",
                   "dependency:advisory_precondition_absent": "medium",
                   **{f"quality:{name}": "medium" for name in QUALITY_CHECKERS}}
RULE_CONTEXT = {EvidenceType.static_source, EvidenceType.reachability, EvidenceType.dependency_resolution}


def check_suggestion(fid: str, verdict: V, codes: tuple[str, ...], evs: list[EvidenceRecord], conf: str,
                     profile_id: str | None = None) -> bool:
    if not evs:  # a verdict must cite evidence
        return False
    if not profile_id and any(e.evidence_type in {
            EvidenceType.runtime_probe, EvidenceType.negative_control, EvidenceType.dast_observation} for e in evs):
        return False
    # some records (e.g. source location) carry no profile id
    profile = profile_id or next((e.deployment_profile_id for e in evs if e.deployment_profile_id), "worksheet")
    try:
        check_verdict(Verdict(verdict_id="probe", finding_id=fid, deployment_profile_id=profile,
                              verdict=verdict, reason_codes=codes, confidence=conf,
                              evidence_ids=tuple(e.evidence_id for e in evs), narrative="-",
                              decided_at=datetime.now(timezone.utc), decided_by={"method": "rules"}),
                      {e.evidence_id: e for e in evs})
        return True
    except InvariantError:
        return False


def suggest_verdict(row: dict, evs: list[EvidenceRecord], *,
                    verified_runtime_ids: frozenset[str] = frozenset()) -> tuple[V, tuple[str, ...], str, list[EvidenceRecord]]:
    """(verdict, reason codes, confidence, cited evidence) for one finding."""
    disp = row["disposition"]
    profile = row.get("deployment_profile_id")
    bound = [e for e in evs if e.evidence_type in
             {EvidenceType.runtime_probe, EvidenceType.negative_control, EvidenceType.dast_observation}]
    if bound and (not profile or any(e.deployment_profile_id != profile for e in bound)):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    if profile and any(e.deployment_profile_id and e.deployment_profile_id != profile for e in evs):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    if disp in SKIP_CODES:  # boundary, dependency and quality rules: decided before any model call
        code, conf = (SKIP_CODES[disp],), SKIP_CONFIDENCE.get(disp, "high")
        verdict = verdict_for(code[0])
        if check_suggestion(row["finding_id"], verdict, code, evs, conf, profile):
            return verdict, code, conf, evs
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs  # e.g. a run made before rule evidence
    if disp.startswith(("surface:", "dependency:", "reachability:")):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    stances = {e.stance for e in evs}
    dast = [e for e in evs if e.evidence_type is EvidenceType.dast_observation and e.stance is Stance.supports]
    if dast and Stance.refutes not in stances and check_suggestion(
            row["finding_id"], V.confirmed, ("DAST_OBSERVED",), evs, "high", profile):
        return V.confirmed, ("DAST_OBSERVED",), "high", evs
    if Stance.supports in stances and Stance.refutes in stances:
        return V.needs_review, ("CONFLICTING_EVIDENCE",), "medium", evs
    runtime = [e for e in evs if e.evidence_type in {EvidenceType.runtime_probe, EvidenceType.negative_control}]
    if (runtime and all(e.evidence_id in verified_runtime_ids for e in runtime)
            and not any(e.evidence_type is EvidenceType.advisory_precondition for e in evs)
            and check_suggestion(row["finding_id"], V.confirmed, ("RUNTIME_CONFIRMED",), evs, "high", profile)):
        return V.confirmed, ("RUNTIME_CONFIRMED",), "high", evs
    # Typed claims alone cannot prove collector provenance. Failed probes stay open.
    if any(e.evidence_type in {EvidenceType.runtime_probe, EvidenceType.advisory_precondition} for e in evs):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    if Stance.non_security in stances and Stance.supports not in stances:
        if check_suggestion(row["finding_id"], V.valid_non_security, ("QUALITY_NOT_SECURITY",), evs, "medium", profile):
            return V.valid_non_security, ("QUALITY_NOT_SECURITY",), "medium", evs
    if Stance.supports in stances:
        code = "VULNERABLE_VERSION_IMPORTED" if row["finding_type"] == "sca" else "STATIC_REACHABLE_SINK"
        if any(e.method == "advisory_call_site:called" for e in evs):
            code = "VULNERABLE_FUNCTION_CALLED"
        if any(e.evidence_type in RULE_CONTEXT for e in evs) and check_suggestion(row["finding_id"], V.likely,
                                                                                  (code,), evs, "medium", profile):
            return V.likely, (code,), "medium", evs
    # A model refutation alone stays needs_review here: which not_applicable reason applies is a reviewer call.
    return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
