"""Luna/Sol model routing for assessment calls (policy: CHECKPOINT.md, "Operating model and model routing").

`codex exec` fixes its model at launch, so routing happens here, per model call:
* junior (Luna) first for clear, bounded, low-ambiguity findings;
* senior (Sol) first for security-sensitive or judgment-bearing findings;
* one escalation junior -> senior when the junior answer is mismatched; no further retries;
* astra only for clusters named explicitly by the caller.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

from fva.reasoning import assessor
from fva.redact import CREDENTIAL_CWES
from fva.schemas import Finding, FindingType, Severity, Stance

JUNIOR, SENIOR, ASTRA, FIXED = "junior", "senior", "astra", "fixed"

DEFAULT_MODELS = {JUNIOR: ("FVA_MODEL_JUNIOR", "gpt-6-luna"), SENIOR: ("FVA_MODEL_SENIOR", "gpt-6-sol"),
                  ASTRA: ("FVA_MODEL_ASTRA", "gpt-6-astra")}

# injection / code execution (incl. eval: 95, 676), SSRF, authn/authz/JWT (incl. untrusted decode 345,
# missing revocation 613), crypto
SENIOR_CWES = {f"CWE-{n}" for n in (78, 79, 89, 94, 95, 676, 943, 918, 284, 285, 287, 345, 347, 613, 639, 862, 863,
                                    320, 326, 327)}
# dead code / no-effect / quality; hard-coded credential vs label checks
JUNIOR_CWES = {f"CWE-{n}" for n in (398, 561, 563)} | CREDENTIAL_CWES

_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


def model_name(tier: str) -> str:
    env, default = DEFAULT_MODELS[tier]
    return os.environ.get(env) or default


def route(group: list[Finding], astra_ids: frozenset[str] = frozenset()) -> tuple[str, str]:
    """(tier, reason) for a cluster. Any senior-worthy member sends the whole cluster to the senior."""
    if astra_ids & {f.source_finding_id for f in group}:
        return ASTRA, "explicit astra flag"
    top = max(group, key=lambda f: _RANK[f.severity]).severity
    cwes = set().union(*(f.cwe for f in group))
    if top is Severity.critical:
        return SENIOR, "critical severity"
    if any(f.finding_type is FindingType.sca for f in group):
        return SENIOR, "sca advisory preconditions"
    if cwes & SENIOR_CWES:
        return SENIOR, "security-sensitive " + ",".join(sorted(cwes & SENIOR_CWES))
    if cwes & JUNIOR_CWES:
        return JUNIOR, "bounded " + ",".join(sorted(cwes & JUNIOR_CWES))
    if top is Severity.high:
        return SENIOR, "high severity, unlisted cwe"
    return JUNIOR, f"{top.value} severity, non-injection"


def escalation_reason(res: assessor.AssessmentResult, group: list[Finding]) -> str | None:
    """Why a junior answer is mismatched and should go to the senior once, or None."""
    if res.unparseable:
        return "unparseable output"
    if res.rejected:
        return "citations rejected"
    if len({c["stance"] for c in res.accepted} - {Stance.neutral.value}) > 1:
        return "conflicting claims"
    # credential literals are redacted and "active" is decided at runtime, so a senior is no surer (run 1: 19/19
    # credential escalations stayed neutral)
    if res.confidence == "low" and not all(set(f.cwe) & CREDENTIAL_CWES for f in group):
        return "low confidence"
    if res.evidence.stance is Stance.refutes and max(_RANK[f.severity] for f in group) >= _RANK[Severity.high]:
        return "refutes high/critical"
    return None


@dataclass
class RoutedResult:
    result: assessor.AssessmentResult
    tier: str
    reason: str
    attempts: list[dict] = field(default_factory=list)


class Router:
    """Holds one client per tier. `clients` maps tier -> ModelClient; missing tiers are built lazily by `make`."""

    def __init__(self, clients: dict, make=None, astra_ids=frozenset()):
        self._clients, self._make, self.astra_ids = dict(clients), make, frozenset(astra_ids)
        self._lock = threading.Lock()  # lazy client creation can race across pipeline worker threads

    @classmethod
    def single(cls, client) -> "Router":
        return cls({FIXED: client})

    @property
    def routed(self) -> bool:
        return FIXED not in self._clients

    @property
    def model_id(self) -> str:
        return "routed" if self.routed else self._clients[FIXED].model_id

    def client(self, tier: str):
        if tier not in self._clients:
            with self._lock:
                if tier not in self._clients:
                    if self._make is None:
                        raise SystemExit(f"no client configured for tier {tier}")
                    self._clients[tier] = self._make(model_name(tier))
        return self._clients[tier]

    def plan(self, group: list[Finding]) -> tuple[str, str]:
        return (FIXED, "routing off") if not self.routed else route(group, self.astra_ids)

    def _call(self, tier, reason, lead, idx, attempts, **kw):
        client = self.client(tier)
        t0 = time.time()
        res = assessor.assess(lead, idx, client, routing={"routing_tier": tier, "routing_reason": reason}, **kw)
        attempts.append({"tier": tier, "model": client.model_id, "agent_model": res.agent_model,
                         "seconds": round(time.time() - t0, 1), "cached": res.cached, "tokens": res.tokens,
                         "usage": res.usage,
                         "stance": res.evidence.stance.value, "confidence": res.confidence,
                         "rejected": len(res.rejected)})
        return res

    def assess(self, group: list[Finding], idx, **kw) -> RoutedResult:
        tier, reason = self.plan(group)
        attempts: list[dict] = []
        res = self._call(tier, reason, group[0], idx, attempts, **kw)
        if tier == JUNIOR:
            why = escalation_reason(res, group)
            if why:
                attempts[-1]["escalate"] = why
                reason = f"escalated from {JUNIOR}: {why}"
                tier = SENIOR
                res = self._call(tier, reason, group[0], idx, attempts, **kw)
        return RoutedResult(res, tier, reason, attempts)
