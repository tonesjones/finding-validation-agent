"""Small, explicit npm advisory ranges, affected functions and option preconditions. Unknown advisories fail closed
to review."""
from __future__ import annotations

from collections.abc import Callable
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
    ("lodash", "CVE-2020-28500"): Range((4, 0, 0), (4, 17, 21)),
    # https://github.com/advisories/GHSA-35jh-r3h4-6jhm
    ("lodash", "CVE-2021-23337"): Range((0, 0, 0), (4, 17, 21)),
    # https://github.com/advisories/GHSA-xxjr-mmjv-4gpg
    ("lodash", "CVE-2025-13465"): Range((4, 0, 0), (4, 17, 23)),
    # Array-path bypass; package advisory describes 4.17.23 as affected.
    # https://github.com/advisories/GHSA-f23m-r3pf-42rh
    ("lodash", "CVE-2026-2950"): Range((0, 0, 0), (4, 17, 24)),
    # Template imports key-name injection; package advisory describes <=4.17.23.
    # https://github.com/advisories/GHSA-r5fr-rjxr-66jc
    ("lodash", "CVE-2026-4800"): Range((4, 0, 0), (4, 17, 24)),
    # https://github.com/advisories/GHSA-rm97-x556-q36h
    ("sanitize-html", "CVE-2024-21501"): Range((0, 0, 0), (2, 12, 1)),
    # https://github.com/advisories/GHSA-rjqq-98f6-6j3r
    ("sanitize-html", "CVE-2021-26539"): Range((0, 0, 0), (2, 3, 1)),
    # https://github.com/advisories/GHSA-mjxr-4v3x-q3m4
    ("sanitize-html", "CVE-2021-26540"): Range((0, 0, 0), (2, 3, 2)),
    # "< 2.0.0-beta"; prerelease versions never parse, so they stay unknown.
    # https://github.com/advisories/GHSA-qhxp-v273-g94h
    ("sanitize-html", "CVE-2019-25225"): Range((0, 0, 0), (2, 0, 0)),
    # Regression in 2.17.2 only. https://github.com/advisories/GHSA-9mrh-v2v3-xpfm
    ("sanitize-html", "CVE-2026-40186"): Range((2, 17, 2), (2, 17, 3)),
    # "<= 2.17.5". https://github.com/advisories/GHSA-jxwj-j7wr-gfrw
    ("sanitize-html", "CVE-2026-63670"): Range((0, 0, 0), (2, 17, 6)),
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


@dataclass(frozen=True)
class OptionPrecondition:
    option: str
    met: Callable[[str | None], bool]  # option value source (None = not passed) -> False only when it cannot apply
    note: str


def _passed(value: str | None) -> bool:
    return value is not None


def _strings(value: str) -> set[str] | None:
    """Items of an array literal of plain string literals; None for anything else."""
    if not (value.startswith("[") and value.endswith("]")):
        return None
    items = [item.strip() for item in value[1:-1].split(",")]
    if items and items[-1] == "":
        items.pop()
    found = [re.fullmatch(r"""(['"])([\w-]*)\1""", item) for item in items]
    return {m.group(2) for m in found} if all(found) else None


def _raw_text_tags(value: str | None) -> bool:
    items = None if value is None else _strings(value)
    return value is not None and (items is None or not items.isdisjoint({"textarea", "xmp"}))


_PRECONDITIONS = {
    # Each advisory names a non-default option; the defaults allow no style attribute, no iframe hostname list, no
    # transformTags and no textarea/xmp tags. "{}" allows no attributes; `false` allows all.
    ("sanitize-html", "CVE-2024-21501"): OptionPrecondition(
        "allowedAttributes", lambda v: v is not None and v != "{}", "the style attribute allowed"),
    ("sanitize-html", "CVE-2021-26539"): OptionPrecondition(
        "allowedIframeHostnames", _passed, "an allowedIframeHostnames list"),
    ("sanitize-html", "CVE-2021-26540"): OptionPrecondition(  # also needs allowIframeRelativeUrls: true
        "allowedIframeHostnames", _passed, "an allowedIframeHostnames list"),
    ("sanitize-html", "CVE-2019-25225"): OptionPrecondition("transformTags", _passed, "the transformTags option"),
    ("sanitize-html", "CVE-2026-63670"): OptionPrecondition("allowedTags", _raw_text_tags, "textarea or xmp in allowedTags"),
}
OPTION_PACKAGES = frozenset(package for package, _ in _PRECONDITIONS)
_MARKUP = (".html", ".htm", ".vue", ".svelte", ".ejs", ".hbs", ".pug")


@dataclass(frozen=True)
class CallScan:
    sites: tuple[tuple[str, str], ...]  # (function, "file:line") in shipped code
    unresolved: tuple[str, ...]  # "file:line" uses the scan could not name


@dataclass(frozen=True)
class OptionScan:
    calls: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]  # ("file:line", ((option, value source), ...))
    unresolved: tuple[str, ...]


def _site_key(site: str) -> tuple[str, int]:
    return site.rsplit(":", 1)[0], int(site.rsplit(":", 1)[1])


def _shipped(root: Path, files: list[str], profile: DeploymentProfile, unresolved: set[str]):
    """(path, text) of shipped Node source and markup files; unreadable files count as unresolved uses."""
    pack = REGISTRY["node"]
    for rel in sorted(files):
        if not rel.endswith(pack.source_suffixes + _MARKUP) or not is_deployed(classify_path(rel, profile), profile):
            continue
        try:
            yield rel, (Path(root) / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            unresolved.add(f"{rel}:1")


def scan_calls(root: Path, files: list[str], profile: DeploymentProfile,
               package: str = "lodash", functions: frozenset[str] = LODASH_FUNCTIONS) -> CallScan:
    """Uses of `package`'s named functions across shipped code (Node pack), with anything unresolvable."""
    pack = REGISTRY["node"]
    glob = re.compile(rf"(?<![\w$.])_\s*\??\.\s*({'|'.join(sorted(functions))})(?![\w$])")  # browser global `_`
    sites, unresolved = set(), set()
    for rel, text in _shipped(root, files, profile, unresolved):
        sites.update((m.group(1), f"{rel}:{text.count(chr(10), 0, m.start()) + 1}") for m in glob.finditer(text))
        if package not in text:
            continue
        found, lines = pack.call_sites(text, package, functions)
        sites.update((fn, f"{rel}:{ln}") for fn, ln in found)
        unresolved.update(f"{rel}:{ln}" for ln in lines)
        if rel.endswith(_MARKUP) and package in text:  # e.g. a <script src=".../lodash.js"> global
            unresolved.add(f"{rel}:{text.count(chr(10), 0, text.index(package)) + 1}")
    return CallScan(tuple(sorted(sites, key=lambda s: (_site_key(s[1]), s[0]))),
                    tuple(sorted(unresolved, key=_site_key)))


def scan_options(root: Path, files: list[str], profile: DeploymentProfile, package: str) -> OptionScan:
    """Direct calls of `package`'s default export across shipped code with their literal options."""
    calls, unresolved = [], set()
    for rel, text in _shipped(root, files, profile, unresolved):
        if package not in text:
            continue
        if rel.endswith(_MARKUP):  # a bundled browser copy cannot be followed
            unresolved.add(f"{rel}:{text.count(chr(10), 0, text.index(package)) + 1}")
            continue
        found, lines = REGISTRY["node"].option_calls(text, package)
        calls.extend((f"{rel}:{ln}", tuple(sorted(options.items()))) for ln, options in found)
        unresolved.update(f"{rel}:{ln}" for ln in lines)
    return OptionScan(tuple(sorted(calls, key=lambda c: _site_key(c[0]))), tuple(sorted(unresolved, key=_site_key)))


def scan(root: Path, files: list[str], profile: DeploymentProfile, package: str) -> CallScan | OptionScan:
    return scan_options(root, files, profile, package) if package in OPTION_PACKAGES else scan_calls(root, files, profile)


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


def called_at(finding: Finding, scan: CallScan | OptionScan) -> list[tuple[str, int]]:
    """(path, line) of shipped calls of the advisory's functions, for showing the code to a reviewer or model."""
    pkg = finding.package
    rule = _FUNCTIONS.get(pkg.advisory_id or "") if pkg and pkg.name.lower() == "lodash" else None
    if not isinstance(scan, CallScan):
        return []
    return [(s.rsplit(":", 1)[0], int(s.rsplit(":", 1)[1])) for fn, s in scan.sites if rule and fn in rule.functions]


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


def precondition_status(finding: Finding, scan: OptionScan, dependents: list[str] | None) -> tuple[str, str] | None:
    """(status, detail) for an advisory that needs a non-default option; None when no precondition entry applies."""
    pkg = finding.package
    rule = _PRECONDITIONS.get((pkg.name.lower(), pkg.advisory_id or "")) if pkg else None
    if rule is None:
        return None
    hits = [site for site, options in scan.calls if rule.met(dict(options).get(rule.option))]
    if hits:
        return "precondition_possible", f"{rule.option} set at " + ", ".join(hits[:10])
    if scan.unresolved:
        return "unresolved_use", "unresolved uses at " + ", ".join(scan.unresolved[:10])
    if dependents is None:
        return "no_lockfile", "installed dependents unknown"
    if dependents:
        return "installed_dependents", "other installed packages depend on it: " + ", ".join(dependents[:5])
    return "precondition_absent", f"none of {len(scan.calls)} shipped call(s) sets it"


def precondition_evidence(finding: Finding, status: str, detail: str, profile_id: str | None = None) -> EvidenceRecord:
    pkg = finding.package
    rule = _PRECONDITIONS[(pkg.name.lower(), pkg.advisory_id)]
    return EvidenceRecord(
        evidence_id=f"{finding.finding_id}:option:{status}",
        finding_ids=(finding.finding_id,),
        evidence_type=EvidenceType.static_source,
        method=f"advisory_option:{status}",
        stance=Stance.refutes if status == "precondition_absent" else Stance.neutral,
        summary=f"{pkg.advisory_id} needs {rule.note} ({pkg.name} option {rule.option}): {detail}"[:1000],
        deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
        tool_versions={"advisory_option": rule.option},
    )


def use_evidence(finding: Finding, scan: CallScan | OptionScan, dependents: list[str] | None,
                 profile_id: str | None = None) -> tuple[EvidenceRecord, str | None] | None:
    """(record, pipeline skip disposition when it refutes) from the package's call-site or option rule."""
    if isinstance(scan, OptionScan):
        status = precondition_status(finding, scan, dependents)
        return status and (precondition_evidence(finding, *status, profile_id),
                           "dependency:advisory_precondition_absent" if status[0] == "precondition_absent" else None)
    status = call_site_status(finding, scan, dependents)
    return status and (call_site_evidence(finding, *status, profile_id),
                       "dependency:vulnerable_function_not_called" if status[0] == "not_called" else None)


def _version(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"([0-9]{1,18})\.([0-9]{1,18})\.([0-9]{1,18})", value, flags=re.ASCII)
    if not match or any(len(part) > 1 and part.startswith("0") for part in match.groups()):
        return None
    return tuple(map(int, match.groups()))


def applicable(finding: Finding, installed_version: str) -> bool | None:
    """True/False only for a supported exact npm package/advisory/version tuple."""
    pkg = finding.package
    if not pkg or (pkg.ecosystem or "").lower() != "npm":
        return None
    rule = _RANGES.get((pkg.name.lower(), pkg.advisory_id or ""))
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
        summary=f"{finding.package.advisory_id} range check: {finding.package.name} {installed_version} is {status}",
        deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
    )
