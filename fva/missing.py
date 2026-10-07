"""Plain-language report gaps derived only from safe finding/evidence metadata."""
from __future__ import annotations

import re

from fva.invariants import RULE_TYPES
from fva.redact import redact
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Surface


EXCEPTION_GAPS = {
    "PROFILE_MISMATCH": "evidence bound to the run's deployment profile is missing",
    "UNVERIFIED_RUNTIME": "verified collector receipts and a linked negative control are needed for the runtime evidence",
    "CONFLICTING_EVIDENCE": "evidence resolving the supporting and refuting observations is missing",
    "MODEL_ONLY_REFUTATION": "the model argues for closure, but no rule-derived evidence backs it",
    "HIGH_IMPACT_CLOSURE": "closing this high or critical issue needs high-confidence rule evidence",
    "LOW_CONFIDENCE": "evidence strong enough to meet the automatic decision's confidence requirement is missing",
}
_SECRET = "evidence of whether the value is a live secret used by shipped code, or a placeholder, test fixture or public value, is missing"
_EVAL = "evidence of whether untrusted input reaches dynamic code evaluation is missing"
SAST_CWE_GAPS = {
    "CWE-798": _SECRET,
    "CWE-259": _SECRET,
    "CWE-321": _SECRET,
    "CWE-79": "evidence of whether untrusted input reaches the output sink without context-appropriate encoding or sanitizing is missing",
    "CWE-89": "evidence of whether untrusted input reaches the query without parameterization is missing",
    "CWE-78": "evidence of whether untrusted input reaches the command without an allowlist or safe argument passing is missing",
    "CWE-22": "evidence of whether untrusted input reaches the file path without normalization and a base-directory check is missing",
    "CWE-918": "evidence of whether untrusted input controls the outbound request target without an allowlist is missing",
    "CWE-601": "evidence of whether untrusted input controls the redirect target without an allowlist is missing",
    "CWE-476": "evidence of whether a null or undefined value can reach the dereference on a deployed path is missing",
    "CWE-398": "evidence that this code-quality defect has a security consequence on a deployed path is missing",
    "CWE-94": _EVAL,
    "CWE-95": _EVAL,
}
DEPENDENCY_CHECKS = {
    "version_drift": "scanner versus installed version",
    "not_installed": "package installation",
    "unresolved_name": "package-name resolution",
    "scanned_version_present": "installed version",
    "advisory_version_unaffected": "advisory version applicability",
    "vulnerable_function_not_called": "vulnerable-function call-site",
    "advisory_precondition_absent": "advisory precondition",
}


def _package(finding: dict) -> str:
    # Pipeline rows store name@version. Accept package names only, never arbitrary text or URLs.
    value = finding.get("package")
    if isinstance(value, dict):
        value = value.get("name")
    if isinstance(value, str):
        name = value.rsplit("@", 1)[0] if "@" in value[1:] else value
        if re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-zA-Z0-9_.-]{1,100}", name) and redact(name) == name:
            return name
    return "the reported package"


def missing_evidence(verdict: str, reason_codes, exceptions, finding: dict,
                     cited: list[EvidenceRecord]) -> str:
    """One sentence per open finding; multiple known gaps are joined without raw payloads."""
    codes = set(reason_codes) | set(exceptions)
    stances = {e.stance for e in cited}
    if Stance.supports in stances and Stance.refutes in stances:
        codes.add("CONFLICTING_EVIDENCE")
    refutations = [e for e in cited if e.stance in {Stance.refutes, Stance.non_security}]
    if refutations and all(e.evidence_type == EvidenceType.model_assessment for e in refutations):
        codes.add("MODEL_ONLY_REFUTATION")
    gaps = [text for code, text in EXCEPTION_GAPS.items() if code in codes]
    family, _, check = (finding.get("disposition") or "").partition(":")
    if family == "dependency":
        label = DEPENDENCY_CHECKS.get(check, "dependency")
        result = ("call-site scan or advisory-precondition result" if check in {
            "vulnerable_function_not_called", "advisory_precondition_absent"}
            else "lockfile resolution or advisory applicability result")
        gaps.append(f"the {label} check is inconclusive, so a decisive {result} for {_package(finding)} is missing")
    elif family == "reachability":
        gaps.append("static import-path evidence from a deployed entrypoint is insufficient to establish or rule out reachability")
    elif family == "surface":
        label = check.replace("_", " ") if check in {s.value for s in Surface} else "unclassified"
        gaps.append(f"deployment evidence confirming whether the file's {label} surface ships is missing")
    if verdict == "likely":
        gaps.append("runtime, DAST or imported evidence is needed to confirm this issue; static and model evidence cannot confirm it")
    if not gaps:
        if verdict == "confirmed":
            return "No evidence is missing for confirmation; this confirmed issue remains open for remediation."
        if not cited:
            gaps.append("cited evidence supporting a decision is missing")
        elif any(e.evidence_type in {EvidenceType.runtime_probe, EvidenceType.advisory_precondition} for e in cited):
            gaps.append("verified runtime evidence with a linked negative control or rule-derived advisory-precondition evidence is needed")
        elif finding.get("finding_type") == "dast":
            gaps.append("supporting DAST evidence linked to this finding and the run's deployment profile is needed")
        elif Stance.supports in stances and not any(e.evidence_type in RULE_TYPES for e in cited):
            gaps.append("rule-derived source, dependency or reachability evidence backing the supporting claim is missing")
        elif finding.get("finding_type") == "sca":
            gaps.append(f"evidence deciding installed-version applicability and deployed use of {_package(finding)} is missing")
        elif finding.get("finding_type") == "sast":
            gap = next((SAST_CWE_GAPS[c] for c in finding.get("cwe") or []
                        if isinstance(c, str) and c in SAST_CWE_GAPS), None)
            gaps.append(gap or "source or reachability evidence deciding whether the reported security condition applies is missing")
        else:
            gaps.append("evidence sufficient to decide whether this issue applies is missing")
    sentence = "; ".join(gaps)
    return sentence[0].upper() + sentence[1:] + "."
