"""Cross-record rules. Enforced in code after any rules/LLM step, never trusted to a prompt."""
from __future__ import annotations

from collections.abc import Mapping

from fva import reason_codes
from fva.schemas import EvidenceRecord, Stance, Verdict, VerdictValue

_REQUIRED_STANCE = {
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
    if Stance.supports in stances and Stance.refutes in stances:
        raise InvariantError("conflicting evidence must be needs_review (CONFLICTING_EVIDENCE)")
    need = _REQUIRED_STANCE[v.verdict]
    if need not in stances:
        raise InvariantError(f"{v.verdict.value} requires at least one '{need.value}' evidence record")
