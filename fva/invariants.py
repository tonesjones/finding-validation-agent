"""Cross-record rules. Enforced in code after any rules/LLM step, never trusted to a prompt."""
from __future__ import annotations

from collections.abc import Mapping

from fva import reason_codes
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue

# Evidence types that may carry a confirmation. Static claims and model output never can.
CONFIRMING_TYPES = {EvidenceType.runtime_probe, EvidenceType.human_review,
                    EvidenceType.imported_assessment, EvidenceType.dast_observation}

# Rule-derived evidence a `likely` verdict must cite besides any model claim: a model argument alone never
# makes a finding likely. These are never confirming types.
RULE_TYPES = {EvidenceType.static_source, EvidenceType.deployment_boundary, EvidenceType.dependency_resolution,
              EvidenceType.reachability, EvidenceType.advisory_precondition}

_REQUIRED_STANCE = {
    VerdictValue.likely: Stance.supports,
    VerdictValue.confirmed: Stance.supports,
    VerdictValue.not_applicable: Stance.refutes,
    VerdictValue.valid_non_security: Stance.non_security,
}


class InvariantError(ValueError):
    pass


def check_verdict(v: Verdict, evidence: Mapping[str, EvidenceRecord]) -> None:
    """Raise InvariantError if `v` is not justified by `evidence` (id -> record)."""
    for code in v.reason_codes:
        if reason_codes.verdict_for(code) != v.verdict:
            raise InvariantError(f"{code} is not a {v.verdict.value} reason code")

    cited = []
    for eid in v.evidence_ids:
        rec = evidence.get(eid)
        if rec is None:
            raise InvariantError(f"verdict cites missing evidence {eid}")
        if v.finding_id not in rec.finding_ids:
            raise InvariantError(f"evidence {eid} does not cover finding {v.finding_id}")
        cited.append(rec)

    stances = {r.stance for r in cited}
    if v.verdict is VerdictValue.needs_review:
        return
    if any(r.deployment_profile_id and r.deployment_profile_id != v.deployment_profile_id for r in cited):
        raise InvariantError("evidence deployment profile does not match verdict")
    if Stance.supports in stances and Stance.refutes in stances:
        raise InvariantError("conflicting evidence must be needs_review (CONFLICTING_EVIDENCE)")
    if v.verdict is VerdictValue.confirmed and not any(
            r.stance is Stance.supports and r.evidence_type in CONFIRMING_TYPES for r in cited):
        raise InvariantError("confirmed requires supporting runtime, DAST, imported assessment or human evidence")
    imported = v.decided_by.get("method") == "import" and all(
        r.evidence_type is EvidenceType.imported_assessment for r in cited)
    if "RUNTIME_CONFIRMED" in v.reason_codes and not imported:
        probes = [r for r in cited if r.evidence_type is EvidenceType.runtime_probe and r.stance is Stance.supports]
        controls = [r for r in cited if r.evidence_type is EvidenceType.negative_control and r.stance is Stance.neutral]
        if not any(c.tool_versions.get("control_for") == p.evidence_id for p in probes for c in controls):
            raise InvariantError("RUNTIME_CONFIRMED requires a neutral negative control linked to its probe")
    if v.verdict is VerdictValue.likely and not any(
            r.evidence_type in RULE_TYPES and r.stance in (Stance.supports, Stance.neutral) for r in cited):
        raise InvariantError("likely requires rule-derived static evidence, not model output alone")
    need = _REQUIRED_STANCE[v.verdict]
    if need not in stances:
        raise InvariantError(f"{v.verdict.value} requires at least one '{need.value}' evidence record")
