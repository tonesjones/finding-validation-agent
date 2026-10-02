"""Deployment-boundary classification: which surface does a finding sit on?

Rule precedence: profile extra_path_rules > language packs > generic rules.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fva.langpacks import REGISTRY, glob_match
from fva.langpacks.generic import GENERIC_RULES
from fva.schemas import DeploymentProfile, EvidenceRecord, EvidenceType, Finding, FindingType, Stance, Surface

METHOD = "fva.surface@0.1.0"
_NS = uuid.UUID("3c8e1f2a-6b4d-4e7a-9c5b-2d1f0e9a8b7c")


def match_rule(path: str, profile: DeploymentProfile) -> tuple[Surface, str | None]:
    """(surface, the path rule that decided it); no rule means production_candidate."""
    rules = list(profile.extra_path_rules)
    for name in profile.language_packs:
        rules.extend(REGISTRY[name].path_rules)
    rules.extend(GENERIC_RULES)
    for pattern, surface in rules:
        if glob_match(path, pattern):
            return surface, pattern
    return Surface.production_candidate, None


def classify_path(path: str, profile: DeploymentProfile) -> Surface:
    return match_rule(path, profile)[0]


def classify_finding(f: Finding, profile: DeploymentProfile) -> Surface:
    if f.finding_type is FindingType.sca and f.location is None:
        return Surface.dependency
    if f.location is None:
        return Surface.unknown
    return classify_path(f.location.path, profile)


def is_deployed(surface: Surface, profile: DeploymentProfile) -> bool:
    return surface in profile.deployed_surfaces


def to_evidence(f: Finding, profile: DeploymentProfile) -> EvidenceRecord:
    """Deployment-boundary record: `refutes` when a rule puts the finding outside the deployment; an
    unclassifiable finding (no location, not SCA) is neutral, never a refutation."""
    path = f.location.path if f.location else None
    surface, pattern = match_rule(path, profile) if path else (classify_finding(f, profile), None)
    deployed = is_deployed(surface, profile)
    where = f"{path} is" if path else "finding has no source location;"
    rule = f"path rule '{pattern}'" if pattern else "no path rule matched" if path else "finding kind"
    return EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, f"{f.finding_id}:{profile.profile_id}")), finding_ids=(f.finding_id,),
        evidence_type=EvidenceType.deployment_boundary, method=f"path_rule:{surface.value}",
        stance=Stance.neutral if deployed or surface is Surface.unknown else Stance.refutes,
        summary=f"{where} {surface.value} ({rule}); {'inside' if deployed else 'outside'} deployment "
                f"'{profile.profile_id}'",
        detail_ref=pattern, deployment_profile_id=profile.profile_id, collected_at=datetime.now(timezone.utc),
        tool_versions={"method": METHOD})
