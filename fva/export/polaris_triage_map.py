"""fva verdict -> suggested Polaris triage values. One table, so the later API writer and the worksheet agree.

ASSUMED: status and severity labels are placeholders until checked against the Polaris triage docs/API
(roadmap v0.8). The worksheet shows them as suggestions only; nothing is written to Polaris.
"""
from __future__ import annotations

from fva.schemas import VerdictValue as V

MAP_STATUS = "ASSUMED"

TRIAGE_STATUS = {
    V.confirmed: "To be fixed",
    V.likely: "To be fixed",
    V.needs_review: "Not triaged",
    V.not_applicable: "Dismissed: not applicable",
    V.valid_non_security: "Dismissed: not a security issue",
}

# None = keep the scanner's severity.
SEVERITY_OVERRIDE = {
    V.confirmed: None,
    V.likely: None,
    V.needs_review: None,
    V.not_applicable: "informational",
    V.valid_non_security: "low",
}


def suggest(verdict: V, scanner_severity: str) -> tuple[str, str]:
    return TRIAGE_STATUS[verdict], SEVERITY_OVERRIDE[verdict] or scanner_severity
