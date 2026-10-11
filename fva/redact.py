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
_HEADERS = re.compile(
    r"(?im)^([ \t]*(?:cf-access-client-id|cf-access-client-secret|cf-access-jwt-assertion|authorization)"
    r"[ \t]*:)[ \t]*[^\r\n]+")
_DYNAMIC_CREDENTIAL_REF = re.compile(
    r"(?:Bearer |Basic )?\$\{[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(\))?\}", re.I)

# CWEs where any string literal on the line may itself be the secret
CREDENTIAL_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-547"}


def redact(text: str, *, all_strings: bool = False) -> str:
    for p in _PATTERNS:
        text = p.sub(MASK, text)
    text = _ASSIGN.sub(lambda m: m.group(0) if m.group(2) == "`" and
                       _DYNAMIC_CREDENTIAL_REF.fullmatch(m.group(3))
                       else f"{m.group(1)}{m.group(2)}{MASK}{m.group(2)}", text)
    if all_strings:
        text = _STRING.sub(lambda m: f"{m.group(1)}{MASK}{m.group(1)}" if m.group(2) else m.group(0), text)
    return text


_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def redact_lines(lines: list[str], *, all_strings: bool = False) -> list[str]:
    """Redact source lines one by one, first masking whole PEM private-key blocks.

    A block runs from its BEGIN line through its END line; with no END it runs to the end of the file
    (fail closed). The line count never changes, so line numbers stay valid."""
    out, inside = [], False
    for line in lines:
        if not inside and _KEY_BEGIN.search(line):
            inside = True
        if inside:
            out.append(MASK)
            if _KEY_END.search(line):
                inside = False
        else:
            out.append(redact(line, all_strings=all_strings))
    return out


def redact_http(text: str) -> str:
    """Mask complete credential headers in HTTP evidence, preserving source syntax elsewhere."""
    return redact(_HEADERS.sub(lambda m: f"{m.group(1)} {MASK}", text))


def redact_value(value):
    """Redact strings before JSON serialization escapes header line breaks."""
    if isinstance(value, str):
        return redact_http(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value
