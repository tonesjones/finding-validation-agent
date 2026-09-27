"""Explicit severity normalization tables - reviewable, not inferred per adapter."""
from __future__ import annotations

from fva.schemas import Severity

# SARIF result.level
SARIF_LEVEL = {"error": Severity.high, "warning": Severity.medium, "note": Severity.low, "none": Severity.info}

# Vendor strings seen so far (lower-cased)
VENDOR_STRINGS = {
    "critical": Severity.critical, "high": Severity.high, "medium": Severity.medium,
    "moderate": Severity.medium, "low": Severity.low, "info": Severity.info,
    "informational": Severity.info, "audit": Severity.info,
}


def from_cvss(score: float) -> Severity:
    """CVSS v3 qualitative bands (also used by GitHub `security-severity`)."""
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.info


def from_vendor(s: str) -> Severity:
    try:
        return VENDOR_STRINGS[s.strip().lower()]
    except KeyError:
        raise ValueError(f"no severity mapping for {s!r}; add it to fva/severity.py") from None
