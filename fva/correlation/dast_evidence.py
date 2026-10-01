"""SAST<->DAST links -> `dast_observation` runtime evidence.

Only a high-confidence link `supports`; medium/low links are `neutral` context. A SAST finding
with no DAST link gets no record at all: a missing DAST hit is never evidence of absence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fva.schemas import EvidenceRecord, EvidenceType, FindingLink, LinkKind, RuntimeMode, Stance

_NS = uuid.UUID("9e4f1a27-3b6c-4d85-a0e2-7f8c9d0b1a34")


def to_evidence(link: FindingLink, *, profile_id: str, mode: RuntimeMode = RuntimeMode.dast_evidence
                ) -> EvidenceRecord | None:
    if mode is RuntimeMode.none or link.kind is not LinkKind.sast_dast:
        return None
    stance = Stance.supports if link.confidence == "high" else Stance.neutral
    return EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, f"{link.link_id}:{profile_id}")),
        finding_ids=(link.from_finding_id, link.to_finding_id), evidence_type=EvidenceType.dast_observation,
        method=f"dast_link:{link.confidence}", stance=stance,
        summary=f"authorized DAST observation linked ({link.confidence}; basis: {', '.join(link.basis)})",
        deployment_profile_id=profile_id, collected_at=datetime.now(timezone.utc),
        tool_versions={"link_method": link.method})
