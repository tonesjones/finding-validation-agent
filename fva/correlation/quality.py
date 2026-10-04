"""Scanner checkers whose findings are code-quality defects by definition, never a security flaw.

Keyed on the scanner's checker id (Polaris `rule_id` before any `|language` suffix), not on CWE: CWE-398 also
covers checkers such as copy_paste_error whose defect can carry security impact. Unknown checkers are not listed.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fva.schemas import EvidenceRecord, EvidenceType, Finding, FindingType, Stance

QUALITY_CHECKERS = {
    # Coverity NO_EFFECT ("Unreachable, Unused or Dead Code"): a statement or expression that changes nothing.
    "no_effect": "a statement or expression with no effect",
}


def checker(f: Finding) -> str | None:
    """The finding's quality checker name, or None when it is not a listed SAST quality checker."""
    name = (f.rule_id or "").split("|", 1)[0].strip().lower()
    return name if f.finding_type is FindingType.sast and name in QUALITY_CHECKERS else None


def to_evidence(f: Finding, name: str, profile_id: str | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"{f.finding_id}:quality:{name}",
        finding_ids=(f.finding_id,),
        evidence_type=EvidenceType.static_source,
        method=f"quality_checker:{name}",
        stance=Stance.non_security,
        summary=f"Checker {f.rule_id} reports {QUALITY_CHECKERS[name]}: a code-quality defect, not a vulnerability.",
        deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
    )
