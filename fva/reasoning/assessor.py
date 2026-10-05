"""LLM assessment -> `model_assessment` evidence with verified citations.

Rules enforced in code (not trusted to the prompt):
* every citation must point at an existing line of the pinned source, and its quote must
  appear on that line (+/-2, whitespace-insensitive, compared on redacted text);
* a claim whose citations all fail is rejected; a claim with no citations is kept as neutral;
* suggested reason codes must exist in the vocabulary and match the claim's stance;
* the model's evidence can never by itself justify `confirmed` (see fva.invariants).
Only redacted code is ever sent to the model.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fva import reason_codes
from fva.correlation.locate import SourceIndex
from fva.redact import CREDENTIAL_CWES, redact
from fva.schemas import EvidenceRecord, EvidenceType, Finding, FindingType, Stance, VerdictValue

PROMPT_VERSION = "assess-v2"
_NS = uuid.UUID("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
CONTEXT_LINES = 15
# Codes a model may suggest. Triage-routing and reviewer codes describe people and policy, and passive-observation
# codes describe collector receipts, not code.
MODEL_CODES = tuple(sorted(set(reason_codes.CODES) - {
    "LOW_CONFIDENCE", "MODEL_ONLY_REFUTATION", "PROFILE_MISMATCH", "UNVERIFIED_RUNTIME", "HIGH_IMPACT_CLOSURE",
    "REVIEWER_CONFIRMED", "REVIEWER_NOT_APPLICABLE", "PACKAGE_NOT_LOADED", "EXECUTED_UNDER_TEST"}))
# Refutations that name a missing precondition; one with a verified citation outranks a restated sink.
PRECONDITION_CODES = {"NO_ATTACKER_CONTROL", "TRUSTED_SOURCE", "MITIGATED_IN_CONTEXT", "ADVISORY_PRECONDITION_ABSENT",
                      "VULNERABLE_FUNCTION_NOT_CALLED"}

SYSTEM = """You are a security reviewer validating ONE static-analysis or dependency finding against source code.
You do not decide the final verdict. You make specific, checkable claims.

Rules:
- Every claim must cite exact code: repo-relative path, 1-based line number, and a short verbatim quote from that line.
- Only cite code shown to you. Never invent files, lines, or quotes. Values shown as [REDACTED] stay redacted.
- stance:
  "supports": you can cite how attacker-influenced input or an attacker-reachable path gets to the flagged code
    (for a dependency: an affected function called with attacker-influenced arguments).
  "refutes": you can cite the missing precondition: the input is constant or trusted, a control blocks it, the code
    is unreachable, or (for a dependency) the affected functions are not called or only with constant arguments.
  "non_security": the code has a real quality or reliability problem (dead code, null handling, error handling)
    with no security impact.
  "neutral": context only. Restating what the scanner flagged, or that the sink exists, is neutral, not supports.
- If you cannot tell, say so with a neutral claim. Uncertainty is acceptable; guessing is not.
- suggested_reason_code must be one of the codes listed, or null.

Reply with JSON only:
{"claims":[{"statement":"...","stance":"supports|refutes|non_security|neutral",
 "suggested_reason_code":"CODE or null","citations":[{"path":"...","line":123,"quote":"..."}]}],
 "confidence":"high|medium|low"}"""


@dataclass
class AssessmentResult:
    finding_id: str
    evidence: EvidenceRecord
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    cached: bool = False
    confidence: str = "low"
    unparseable: bool = False
    agent_model: str = ""  # model the client reported running (e.g. Codex's `model:` header), else its id
    tokens: int | None = None  # tokens the client reported for the call (from cache meta on a cache hit)
    usage: dict | None = None  # exact token usage of the call that made the answer (from cache meta on a hit)


def _window(idx: SourceIndex, path: str, line: int, redact_all: bool) -> str:
    lines = idx.lines(path)
    lo, hi = max(1, line - CONTEXT_LINES), min(len(lines), line + CONTEXT_LINES)
    return "\n".join(f"{n:5d}| {redact(lines[n - 1].rstrip(), all_strings=redact_all)}" for n in range(lo, hi + 1))


def build_prompt(f: Finding, idx: SourceIndex, evidence: list[EvidenceRecord], sites: list[tuple[str, int]]) -> str:
    redact_all = bool(set(f.cwe) & CREDENTIAL_CWES)
    parts = [f"FINDING\n  tool: {f.source_tool}\n  rule: {f.rule_id}\n  title: {f.title}\n  cwe: {', '.join(f.cwe) or '-'}\n"
             f"  severity: {f.severity.value}\n  type: {f.finding_type.value}"]
    if f.description:
        parts.append("DESCRIPTION\n" + f.description[:2000])
    if f.package:
        m = f.scanner_metadata
        parts.append(f"PACKAGE {f.package.name} {f.package.version} ({f.package.ecosystem or '?'}) advisory {f.package.advisory_id}"
                     + (f"\n  fix: {m['fix_guidance']}" if m.get("fix_guidance") else ""))
    if evidence:
        parts.append("EXISTING EVIDENCE\n" + "\n".join(f"- [{e.evidence_type.value}/{e.stance.value}] {e.summary[:600]}"
                                                        for e in evidence))
    shown = []
    if f.finding_type is FindingType.sast and f.location and f.location.start_line and f.location.path in idx.files:
        shown.append((f.location.path, f.location.start_line))
    shown += [s for s in sites if s[0] in idx.files][:5]
    for path, line in shown:
        parts.append(f"CODE {path} (around line {line})\n" + _window(idx, path, line, redact_all))
    allowed = ", ".join(MODEL_CODES)
    parts.append(f"ALLOWED REASON CODES\n{allowed}")
    return "\n\n".join(parts)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def verify_citation(c: dict, idx: SourceIndex, redact_all: bool) -> bool:
    path, line, quote = c.get("path"), c.get("line"), _norm(str(c.get("quote", "")))
    if not isinstance(path, str) or path not in idx.files or not isinstance(line, int) or line < 1 or len(quote) < 3:
        return False
    lines = idx.lines(path)
    if line > len(lines):
        return False
    for n in range(max(1, line - 2), min(len(lines), line + 2) + 1):
        if quote in _norm(redact(lines[n - 1], all_strings=redact_all)):
            return True
    return False


_STANCE_VERDICT = {Stance.supports: VerdictValue.confirmed, Stance.refutes: VerdictValue.not_applicable,
                   Stance.non_security: VerdictValue.valid_non_security, Stance.neutral: VerdictValue.needs_review}


def _check_claims(raw: dict, idx: SourceIndex, redact_all: bool):
    accepted, rejected = [], []
    for c in raw.get("claims") or []:
        try:
            stance = Stance(c.get("stance"))
        except ValueError:
            rejected.append({**c, "_why": "invalid stance"})
            continue
        cites = c.get("citations") or []
        good = [x for x in cites if verify_citation(x, idx, redact_all)]
        if cites and not good:
            rejected.append({**c, "_why": "no citation verified"})
            continue
        code = c.get("suggested_reason_code")
        if code and (code not in reason_codes.CODES or reason_codes.CODES[code].verdict != _STANCE_VERDICT[stance]):
            code = None
        accepted.append({"statement": str(c.get("statement", ""))[:500],
                         "stance": stance.value if good else Stance.neutral.value,
                         "suggested_reason_code": code, "citations": good,
                         "dropped_citations": len(cites) - len(good)})
    return accepted, rejected


def _aggregate(accepted: list[dict], sink: tuple[str, int] | None = None) -> Stance:
    st = {Stance(c["stance"]) for c in accepted} - {Stance.neutral}
    if len(st) == 1:
        return st.pop()
    if st == {Stance.supports, Stance.refutes} and sink:
        # A cited missing precondition beats supports claims that only point at the flagged line itself.
        def at_sink(c):
            return all(x["path"] == sink[0] and abs(x["line"] - sink[1]) <= 2 for x in c["citations"])
        if (all(at_sink(c) for c in accepted if c["stance"] == Stance.supports.value)
                and any(c["stance"] == Stance.refutes.value and c["suggested_reason_code"] in PRECONDITION_CODES
                        and c["citations"] and not at_sink(c) for c in accepted)):
            return Stance.refutes
    return Stance.neutral  # none, or conflicting directions


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("model returned no JSON object")
    return json.loads(m.group(0))


def assess(f: Finding, idx: SourceIndex, client, *, source_content_sha256: str, profile_id: str,
           evidence: list[EvidenceRecord] = (), sites: list[tuple[str, int]] = (),
           cache_dir: Path | None = None, also_covers: tuple[str, ...] = (),
           routing: dict[str, str] | None = None) -> AssessmentResult:
    """`also_covers`: ids of other findings at the same code/advisory; the evidence covers them too.
    `routing`: routing_tier / routing_reason recorded in tool_versions (not part of the cache key)."""
    evidence = list(evidence)
    prompt = build_prompt(f, idx, evidence, list(sites))
    if also_covers:
        prompt += f"\n\nNOTE: {len(also_covers)} other scanner finding(s) report this same location/advisory; your claims apply to all of them."
    # cache_tag: output-mode changes that alter answers without changing the prompt (e.g. an enforced schema)
    parts = [PROMPT_VERSION, client.model_id, f.finding_id, source_content_sha256,
             hashlib.sha256(prompt.encode()).hexdigest()] + ([client.cache_tag] if getattr(client, "cache_tag", "") else [])
    key = hashlib.sha256("\0".join(parts).encode()).hexdigest()
    cached = False
    cache_file = cache_dir / f"{key}.json" if cache_dir else None
    meta_file = cache_dir / f"{key}.meta.json" if cache_dir else None
    meta = {"agent_model": client.model_id, "tokens": None, "usage": None}
    if cache_file and cache_file.exists():
        text, cached = cache_file.read_text(encoding="utf-8"), True
        if meta_file.exists():
            meta.update({k: v for k, v in json.loads(meta_file.read_text(encoding="utf-8")).items() if v})
    else:
        text = client.complete(SYSTEM, prompt)
        meta = {"agent_model": getattr(client, "last_reported_model", None) or client.model_id,
                "tokens": getattr(client, "last_tokens", None), "usage": getattr(client, "last_usage", None)}
        if cache_file:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(text, encoding="utf-8")
            meta_file.write_text(json.dumps(meta), encoding="utf-8")
    agent_model = meta["agent_model"]
    redact_all = bool(set(f.cwe) & CREDENTIAL_CWES)
    unparseable = False
    try:
        raw = _parse(text)
        accepted, rejected = _check_claims(raw, idx, redact_all)
        conf = raw.get("confidence") if raw.get("confidence") in ("high", "medium", "low") else "low"
    except (ValueError, json.JSONDecodeError) as e:
        accepted, rejected, conf, unparseable = [], [{"_why": f"unparseable response: {e}"}], "low", True
    loc = f.location
    stance = _aggregate(accepted, (loc.path, loc.start_line) if loc and loc.start_line else None)
    lines = [f"model {client.model_id} ({PROMPT_VERSION}), self-reported confidence {conf}; "
             f"{len(accepted)} claim(s) accepted, {len(rejected)} rejected"]
    for c in accepted:
        cites = ", ".join(f"{x['path']}:{x['line']}" for x in c["citations"]) or "no citation"
        lines.append(f"- [{c['stance']}] {c['statement']} ({cites})"
                     + (f" -> {c['suggested_reason_code']}" if c["suggested_reason_code"] else ""))
    ev = EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, key)), finding_ids=(f.finding_id, *also_covers),
        evidence_type=EvidenceType.model_assessment, method=f"llm:{client.model_id}:{PROMPT_VERSION}",
        stance=stance, summary=redact("\n".join(lines)), deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc),
        tool_versions={"agent_model": agent_model, "requested_model": client.model_id,
                       "prompt_version": PROMPT_VERSION, "source_content_sha256": source_content_sha256,
                       **(routing or {})})
    return AssessmentResult(f.finding_id, ev, accepted, rejected, cached, conf, unparseable, agent_model,
                            meta["tokens"], meta.get("usage"))
