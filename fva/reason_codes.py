"""Closed, versioned reason-code vocabulary.

Append-only: never rename or delete a code once released; deprecate instead.
Seeded from the 16 classifications used in the Juice Shop PoC ledger
(see LEGACY_POC_MAP) plus needs_review codes the PoC folded together.
"""
from __future__ import annotations

from dataclasses import dataclass

from fva.schemas import VerdictValue as V

VOCABULARY_VERSION = "1"


@dataclass(frozen=True)
class ReasonCode:
    code: str
    verdict: V
    description: str


_CODES = [
    # not_applicable - deployment boundary
    ReasonCode("TEST_ONLY", V.not_applicable, "Finding is in test code that is not shipped."),
    ReasonCode("NON_EXECUTABLE_FIXTURE", V.not_applicable, "Sample/teaching code that is never executed."),
    ReasonCode("UNUSED_DEPLOYMENT_CONFIG", V.not_applicable, "Infrastructure/deploy config not used by the tested deployment."),
    ReasonCode("DOCUMENTATION_ONLY", V.not_applicable, "API spec or docs; no executable behaviour."),
    # not_applicable - dependency
    ReasonCode("VERSION_DRIFT", V.not_applicable, "Scanned component version is not the one installed in the tested runtime."),
    ReasonCode("ADVISORY_PRECONDITION_ABSENT", V.not_applicable, "Component present but the advisory's required configuration/usage is absent."),
    ReasonCode("ADVISORY_VERSION_MISMATCH", V.not_applicable, "Advisory does not apply to the installed version."),
    # not_applicable - semantic
    ReasonCode("MITIGATED_IN_CONTEXT", V.not_applicable, "A control in context prevents the issue."),
    ReasonCode("INACTIVE_OR_NON_SECRET", V.not_applicable, "Flagged credential is inactive, a label, or a public identifier."),
    ReasonCode("TRUSTED_SOURCE", V.not_applicable, "Data reaching the sink comes from a trusted source."),
    ReasonCode("NO_ATTACKER_CONTROL", V.not_applicable, "Attacker-controlled input does not reach the sink."),
    # valid_non_security
    ReasonCode("QUALITY_NOT_SECURITY", V.valid_non_security, "Real quality/reliability issue, not a demonstrated vulnerability."),
    # confirmed
    ReasonCode("RUNTIME_CONFIRMED", V.confirmed, "Behaviour confirmed against the live runtime with a control."),
    ReasonCode("RUNTIME_EXPLOITED", V.confirmed, "Advisory/vulnerability exploited against the live runtime."),
    ReasonCode("ACTIVE_CREDENTIAL", V.confirmed, "Hard-coded credential authenticates in the live runtime."),
    ReasonCode("BROWSER_EXECUTION_CONFIRMED", V.confirmed, "Script execution observed in a real browser."),
    ReasonCode("DAST_OBSERVED", V.confirmed, "An authorized DAST scan observed the issue; linked to it with high confidence."),
    # needs_review
    ReasonCode("REACHABLE_NOT_EXPLOITED", V.needs_review, "Vulnerable component is reachable; exact advisory not executed."),
    ReasonCode("UNSAFE_TO_TEST", V.needs_review, "Confirming would require a destructive/DoS test; not run."),
    ReasonCode("PROBE_DID_NOT_REPRODUCE", V.needs_review, "A safe probe did not reproduce; not proof of absence."),
    ReasonCode("CONFLICTING_EVIDENCE", V.needs_review, "Evidence points in both directions."),
    ReasonCode("INSUFFICIENT_EVIDENCE", V.needs_review, "Not enough evidence to decide."),
    # likely (v1 append, 2026-10-01): static evidence only; a human or runtime record is needed to confirm
    ReasonCode("STATIC_REACHABLE_SINK", V.likely, "Shipped, reachable sink with a cited static argument; no runtime proof."),
    ReasonCode("VULNERABLE_VERSION_IMPORTED", V.likely, "Vulnerable version installed and imported by shipped, reachable code; not executed."),
    # human review via the triage worksheet (v1 append, 2026-10-01)
    ReasonCode("REVIEWER_CONFIRMED", V.confirmed, "A named reviewer confirmed the issue from the evidence packet."),
    ReasonCode("REVIEWER_NOT_APPLICABLE", V.not_applicable, "A named reviewer judged the issue not applicable to the shipped app."),
    # passive runtime observation (v1 append, 2026-10-04); deprecated 2026-10-05 when the collectors were removed
    ReasonCode("PACKAGE_NOT_LOADED", V.not_applicable,
               "Package was not loaded by the running app under the recorded exercise, and no shipped code imports it."),
    ReasonCode("EXECUTED_UNDER_TEST", V.likely,
               "Flagged line executed under the recorded exercise, with a cited static or model argument for the issue."),
    # triage exceptions (v1 append, written 2026-10-03, merged 2026-10-04): why `fva.triage` routes a suggestion to a person
    ReasonCode("LOW_CONFIDENCE", V.needs_review, "Suggested verdict is below the confidence triage policy accepts unreviewed."),
    ReasonCode("MODEL_ONLY_REFUTATION", V.needs_review, "Only model output argues the issue is absent; no rule-derived evidence refutes it."),
    ReasonCode("PROFILE_MISMATCH", V.needs_review, "Evidence names no deployment profile or a different one than the run."),
    ReasonCode("UNVERIFIED_RUNTIME", V.needs_review, "Runtime evidence has no verified collector receipt."),
    ReasonCode("HIGH_IMPACT_CLOSURE", V.needs_review, "A high or critical finding would be closed or demoted without high-confidence rule evidence."),
    # advisory call sites (v1 append, written 2026-10-03, merged 2026-10-04)
    ReasonCode("VULNERABLE_FUNCTION_CALLED", V.likely, "Shipped code calls a function the advisory names, on an affected version; not executed."),
    ReasonCode("VULNERABLE_FUNCTION_NOT_CALLED", V.not_applicable, "No shipped code or installed package calls the functions the advisory names."),
]

CODES: dict[str, ReasonCode] = {c.code: c for c in _CODES}

# PoC ledger `classification` -> reason code
LEGACY_POC_MAP: dict[str, str] = {
    "test_only": "TEST_ONLY",
    "non_executable_fixture": "NON_EXECUTABLE_FIXTURE",
    "deployment_specific": "UNUSED_DEPLOYMENT_CONFIG",
    "documentation_only": "DOCUMENTATION_ONLY",
    "stale_dependency_instance": "VERSION_DRIFT",
    "component_present_but_cve_precondition_absent": "ADVISORY_PRECONDITION_ABSENT",
    "mitigated_or_context_not_vulnerable": "MITIGATED_IN_CONTEXT",
    "false_positive_or_inactive_credential": "INACTIVE_OR_NON_SECRET",
    "false_positive_trusted_source": "TRUSTED_SOURCE",
    "false_positive_no_attacker_control": "NO_ATTACKER_CONTROL",
    "valid_quality_finding_not_security": "QUALITY_NOT_SECURITY",
    "true_positive_runtime_validated": "RUNTIME_CONFIRMED",
    "true_positive_runtime_exploited": "RUNTIME_EXPLOITED",
    "true_positive_active_credential": "ACTIVE_CREDENTIAL",
    "true_positive_reachable_xss": "BROWSER_EXECUTION_CONFIRMED",
    "reachable_component_advisory_not_individually_exploited": "REACHABLE_NOT_EXPLOITED",
}


def verdict_for(code: str) -> V:
    try:
        return CODES[code].verdict
    except KeyError:
        raise ValueError(f"unknown reason code {code!r} (vocabulary v{VOCABULARY_VERSION})") from None
