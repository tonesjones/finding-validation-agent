"""Exception-routed triage: which suggested verdicts stand unreviewed and which go to a person.

Every finding gets `route = auto | review`. An `auto` row is a rules suggestion (`fva.verdicts`) that passes
`check_suggestion` and raises no exception below; anything else goes to review with the exception reason codes
that explain why. needs_review is never auto. A model argument alone never closes or demotes a finding.
"""
from __future__ import annotations

from pathlib import Path

from fva.invariants import RULE_TYPES
from fva.schemas import EvidenceRecord, EvidenceType, Severity, Stance, VerdictValue as V
from fva.verdicts import check_suggestion, suggest_verdict

AUTO, REVIEW = "auto", "review"
_CONF = {"low": 0, "medium": 1, "high": 2}
_SEV = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}

# Suggested verdict -> (lowest confidence routed auto, highest severity routed auto below high confidence).
# Verdicts missing here (needs_review) always go to review.
POLICY: dict[V, tuple[str, Severity]] = {
    V.confirmed: ("high", Severity.critical),
    V.likely: ("medium", Severity.critical),
    V.not_applicable: ("medium", Severity.medium),
    V.valid_non_security: ("medium", Severity.medium),
}
CLOSURES = {V.not_applicable, V.valid_non_security}
# Evidence that may justify closing a finding. Model output is absent on purpose.
CLEARING_TYPES = RULE_TYPES | {EvidenceType.human_review, EvidenceType.imported_assessment}
_BOUND = {EvidenceType.runtime_probe, EvidenceType.negative_control, EvidenceType.dast_observation}
_RUNTIME = {EvidenceType.runtime_probe, EvidenceType.negative_control}
# report order for exception reasons
EXCEPTIONS = ("PROFILE_MISMATCH", "UNVERIFIED_RUNTIME", "CONFLICTING_EVIDENCE", "MODEL_ONLY_REFUTATION",
              "HIGH_IMPACT_CLOSURE", "LOW_CONFIDENCE", "INSUFFICIENT_EVIDENCE")


def route(finding_id: str, severity: str, verdict: V, codes: tuple[str, ...], confidence: str,
          cited: list[EvidenceRecord], *, profile: str | None,
          verified_runtime_ids: frozenset[str] = frozenset()) -> tuple[str, tuple[str, ...]]:
    """(route, exception reason codes in EXCEPTIONS order) for one suggested verdict."""
    reasons = set()
    if (any(e.deployment_profile_id and e.deployment_profile_id != profile for e in cited)
            or (not profile and any(e.evidence_type in _BOUND for e in cited))):
        reasons.add("PROFILE_MISMATCH")
    if any(e.evidence_type in _RUNTIME and e.evidence_id not in verified_runtime_ids for e in cited):
        reasons.add("UNVERIFIED_RUNTIME")
    stances = {e.stance for e in cited}
    if Stance.supports in stances and Stance.refutes in stances:
        reasons.add("CONFLICTING_EVIDENCE")
    clearing = [e for e in cited if e.stance in (Stance.refutes, Stance.non_security)]
    if clearing and not any(e.evidence_type in CLEARING_TYPES for e in clearing):
        reasons.add("MODEL_ONLY_REFUTATION")
    if verdict in POLICY:
        min_conf, max_sev = POLICY[verdict]
        if _CONF[confidence] < _CONF[min_conf]:
            reasons.add("LOW_CONFIDENCE")
        if verdict in CLOSURES and confidence != "high" and _SEV[Severity(severity)] > _SEV[max_sev]:
            reasons.add("HIGH_IMPACT_CLOSURE")
        if not reasons and not check_suggestion(finding_id, verdict, codes, cited, confidence, profile):
            reasons.add("INSUFFICIENT_EVIDENCE")
    elif not reasons:  # needs_review with no specific exception: carry the suggestion's own reason
        reasons.update(c for c in codes if c in EXCEPTIONS)
        reasons = reasons or {"INSUFFICIENT_EVIDENCE"}
    return (REVIEW if reasons else AUTO), tuple(c for c in EXCEPTIONS if c in reasons)


def build(run_dir: Path, *, warnings: list[str] | None = None) -> list[dict]:
    """One triage row per original finding in a run, sorted like the worksheet."""
    from fva.export import worksheet
    findings, by_finding, profile, trusted = worksheet.load(run_dir, warnings=warnings)
    rows = []
    for f in findings:
        evs = by_finding.get(f["finding_id"], [])
        verdict, codes, conf, cited = suggest_verdict({**f, "deployment_profile_id": profile}, evs,
                                                      verified_runtime_ids=trusted)
        r, exceptions = route(f["finding_id"], f["severity"], verdict, codes, conf, cited, profile=profile,
                              verified_runtime_ids=trusted)
        rows.append({"finding_id": f["finding_id"], "source_finding_id": f["source_finding_id"],
                     "issue_id": f["issue_id"], "primary": bool(f["primary"]), "scanner": f["finding_type"],
                     "severity": f["severity"], "title": f["title"], "verdict": verdict.value,
                     "reason_codes": list(codes), "confidence": conf, "route": r, "exceptions": list(exceptions),
                     "evidence_ids": [e.evidence_id for e in cited]})
    rows.sort(key=lambda x: (x["issue_id"] or "", not x["primary"], x["source_finding_id"]))
    return rows
