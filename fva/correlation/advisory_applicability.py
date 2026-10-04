"""Small, explicit npm advisory ranges. Unknown advisories fail closed to review."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from fva.schemas import EvidenceRecord, EvidenceType, Finding, Stance


@dataclass(frozen=True)
class Range:
    minimum: tuple[int, int, int]
    maximum_exclusive: tuple[int, int, int]


_RANGES = {
    # Vendor-reviewed GitHub Advisory Database ranges; unknown IDs are never guessed.
    # https://github.com/advisories/GHSA-29mw-wpgm-hmr9
    "CVE-2020-28500": Range((4, 0, 0), (4, 17, 21)),
    # https://github.com/advisories/GHSA-35jh-r3h4-6jhm
    "CVE-2021-23337": Range((0, 0, 0), (4, 17, 21)),
    # https://github.com/advisories/GHSA-xxjr-mmjv-4gpg
    "CVE-2025-13465": Range((4, 0, 0), (4, 17, 23)),
    # Array-path bypass; package advisory describes 4.17.23 as affected.
    # https://github.com/advisories/GHSA-f23m-r3pf-42rh
    "CVE-2026-2950": Range((0, 0, 0), (4, 18, 0)),
    # Template imports key-name injection; package advisory describes <=4.17.23.
    # https://github.com/advisories/GHSA-r5fr-rjxr-66jc
    "CVE-2026-4800": Range((4, 0, 0), (4, 18, 0)),
}


def _version(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"([0-9]{1,18})\.([0-9]{1,18})\.([0-9]{1,18})", value, flags=re.ASCII)
    if not match or any(len(part) > 1 and part.startswith("0") for part in match.groups()):
        return None
    return tuple(map(int, match.groups()))


def applicable(finding: Finding, installed_version: str) -> bool | None:
    """True/False only for a supported exact npm package/advisory/version tuple."""
    pkg = finding.package
    if not pkg or (pkg.ecosystem or "").lower() != "npm" or pkg.name.lower() != "lodash":
        return None
    rule = _RANGES.get(pkg.advisory_id or "")
    version = _version(installed_version)
    if rule is None or version is None:
        return None
    return rule.minimum <= version < rule.maximum_exclusive


def to_evidence(finding: Finding, installed_version: str, result: bool,
                profile_id: str | None = None) -> EvidenceRecord:
    status = "affected" if result else "not_affected"
    stance = Stance.neutral if result else Stance.refutes
    return EvidenceRecord(
        evidence_id=f"{finding.finding_id}:advisory:{installed_version}:{status}",
        finding_ids=(finding.finding_id,),
        evidence_type=EvidenceType.dependency_resolution,
        method=f"advisory_range:{status}",
        stance=stance,
        summary=f"{finding.package.advisory_id} range check: lodash {installed_version} is {status}",
        deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
    )
