"""Small, explicit npm advisory ranges and affected functions. Unknown advisories fail closed to review."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re

from fva.langpacks import REGISTRY
from fva.schemas import DeploymentProfile, EvidenceRecord, EvidenceType, Finding, Stance
from fva.surface import classify_path, is_deployed


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
    "CVE-2026-2950": Range((0, 0, 0), (4, 17, 24)),
    # Template imports key-name injection; package advisory describes <=4.17.23.
    # https://github.com/advisories/GHSA-r5fr-rjxr-66jc
    "CVE-2026-4800": Range((4, 0, 0), (4, 17, 24)),
}


@dataclass(frozen=True)
class AffectedFunctions:
    functions: frozenset[str]
    refutable: bool  # False when the library reaches the flaw from functions not listed here
    note: str = ""


_UNSET = frozenset({"unset", "omit", "pullAt", "dissoc", "dissocPath", "omitAll"})
_FUNCTIONS = {
    # Functions the same advisories name. A missing call refutes only when the flaw has no other entry point.
    "CVE-2020-28500": AffectedFunctions(frozenset({"toNumber", "trim", "trimEnd"}), False,
                                        "toNumber is called internally by many lodash functions"),
    "CVE-2021-23337": AffectedFunctions(frozenset({"template"}), True),
    # pullAt reaches the same baseUnset path; dissoc/dissocPath/omitAll are lodash/fp aliases
    "CVE-2025-13465": AffectedFunctions(_UNSET, True),
    "CVE-2026-2950": AffectedFunctions(_UNSET, True),
    "CVE-2026-4800": AffectedFunctions(frozenset({"template"}), True, "options.imports key names"),
}
LODASH_FUNCTIONS = frozenset().union(*(a.functions for a in _FUNCTIONS.values()))
_MARKUP = (".html", ".htm", ".vue", ".svelte", ".ejs", ".hbs", ".pug")


@dataclass(frozen=True)
class CallScan:
    sites: tuple[tuple[str, str], ...]  # (function, "file:line") in shipped code
    unresolved: tuple[str, ...]  # "file:line" uses the scan could not name


def scan_calls(root: Path, files: list[str], profile: DeploymentProfile,
               package: str = "lodash", functions: frozenset[str] = LODASH_FUNCTIONS) -> CallScan:
    """Uses of `package`'s named functions across shipped code (Node pack), with anything unresolvable."""
    pack = REGISTRY["node"]
    glob = re.compile(rf"(?<![\w$.])_\s*\??\.\s*({'|'.join(sorted(functions))})(?![\w$])")  # browser global `_`
    sites, unresolved = set(), set()
    for rel in sorted(files):
        if not rel.endswith(pack.source_suffixes + _MARKUP) or not is_deployed(classify_path(rel, profile), profile):
            continue
        try:
            text = (Path(root) / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            unresolved.add(f"{rel}:1")
            continue
        sites.update((m.group(1), f"{rel}:{text.count(chr(10), 0, m.start()) + 1}") for m in glob.finditer(text))
        if package not in text:
            continue
        found, lines = pack.call_sites(text, package, functions)
        sites.update((fn, f"{rel}:{ln}") for fn, ln in found)
        unresolved.update(f"{rel}:{ln}" for ln in lines)
        if rel.endswith(_MARKUP) and package in text:  # e.g. a <script src=".../lodash.js"> global
            unresolved.add(f"{rel}:{text.count(chr(10), 0, text.index(package)) + 1}")
    key = lambda s: (s.rsplit(":", 1)[0], int(s.rsplit(":", 1)[1]))  # noqa: E731
    return CallScan(tuple(sorted(sites, key=lambda s: (key(s[1]), s[0]))), tuple(sorted(unresolved, key=key)))


def call_site_status(finding: Finding, scan: CallScan, dependents: list[str] | None) -> tuple[str, str] | None:
    """(status, detail) for a supported lodash advisory; None when no function table entry applies."""
    pkg = finding.package
    rule = _FUNCTIONS.get(pkg.advisory_id or "") if pkg and pkg.name.lower() == "lodash" else None
    if rule is None:
        return None
    hits = [f"{fn} at {site}" for fn, site in scan.sites if fn in rule.functions]
    if hits:
        return "called", "; ".join(hits[:10])
    if not rule.refutable:
        return "internal_callers", rule.note
    if scan.unresolved:
        return "unresolved_use", "unresolved uses at " + ", ".join(scan.unresolved[:10])
    if dependents is None:
        return "no_lockfile", "installed dependents unknown"
    if dependents:
        return "installed_dependents", "other installed packages depend on it: " + ", ".join(dependents[:5])
    return "not_called", "no shipped call of " + ", ".join(sorted(rule.functions))


_CALL_STANCE = {"called": Stance.supports, "not_called": Stance.refutes}


def call_site_evidence(finding: Finding, status: str, detail: str, profile_id: str | None = None) -> EvidenceRecord:
    rule = _FUNCTIONS[finding.package.advisory_id]
    return EvidenceRecord(
        evidence_id=f"{finding.finding_id}:callsite:{status}",
        finding_ids=(finding.finding_id,),
        evidence_type=EvidenceType.static_source,
        method=f"advisory_call_site:{status}",
        stance=_CALL_STANCE.get(status, Stance.neutral),
        summary=f"{finding.package.advisory_id} affects lodash {', '.join(sorted(rule.functions))}: {detail}"[:1000],
        deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
        tool_versions={"advisory_functions": " ".join(sorted(rule.functions))},
    )


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
