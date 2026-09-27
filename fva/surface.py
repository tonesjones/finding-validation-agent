"""Deployment-boundary classification: which surface does a finding sit on?

Rule precedence: profile extra_path_rules > language packs > generic rules.
"""
from __future__ import annotations

from fva.langpacks import REGISTRY, glob_match
from fva.langpacks.generic import GENERIC_RULES
from fva.schemas import DeploymentProfile, Finding, FindingType, Surface


def classify_path(path: str, profile: DeploymentProfile) -> Surface:
    rules = list(profile.extra_path_rules)
    for name in profile.language_packs:
        rules.extend(REGISTRY[name].path_rules)
    rules.extend(GENERIC_RULES)
    for pattern, surface in rules:
        if glob_match(path, pattern):
            return surface
    return Surface.production_candidate


def classify_finding(f: Finding, profile: DeploymentProfile) -> Surface:
    if f.finding_type is FindingType.sca and f.location is None:
        return Surface.dependency
    if f.location is None:
        return Surface.unknown
    return classify_path(f.location.path, profile)


def is_deployed(surface: Surface, profile: DeploymentProfile) -> bool:
    return surface in profile.deployed_surfaces
