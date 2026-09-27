"""Secret redaction. Run BEFORE any evidence is persisted, not just before display."""
from __future__ import annotations

import re

MASK = "[REDACTED]"
_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghs|github_pat|xox[abpr]|sk_live|sk_test)_[A-Za-z0-9_]{10,}"),
    re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+"),
]
# key = "value" / key: 'value' where key looks secret-ish
_ASSIGN = re.compile(
    r"""(?ix)
    (\b[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)[\w.-]*\b
     \s*[:=]\s*)
    (['"`])(.*?)\2""")
_STRING = re.compile(r"""(['"`])((?:\\.|(?!\1).)*)\1""")

# CWEs where any string literal on the line may itself be the secret
CREDENTIAL_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-547"}


def redact(text: str, *, all_strings: bool = False) -> str:
    for p in _PATTERNS:
        text = p.sub(MASK, text)
    text = _ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(2)}", text)
    if all_strings:
        text = _STRING.sub(lambda m: f"{m.group(1)}{MASK}{m.group(1)}" if m.group(2) else m.group(0), text)
    return text
