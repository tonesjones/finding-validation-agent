"""Canonical, vendor-neutral data model.

Record kinds, all append-only:

* IngestionRun   - one import of one raw scanner artifact (pins source commit + raw hash)
* Finding        - one scanner-reported issue, normalized
* EvidenceRecord - one observation; may support several findings (one probe, many rows)
* FindingLink    - a claim that two findings from different scanners describe one flaw
* GroupedIssue   - the connected set of linked findings; every original finding is kept
* Verdict        - one decision for one finding under one deployment profile; never
                   overwritten, a re-decision supersedes the old verdict_id

Cross-record rules (e.g. "confirmed needs supporting evidence") live in
fva.invariants because they need more than one record to check.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingType(str, Enum):
    sast = "sast"
    sca = "sca"
    dast = "dast"


class RuntimeMode(str, Enum):
    """Where runtime evidence may come from. Live probing is never the default."""

    none = "none"  # static evidence only
    dast_evidence = "dast-evidence"  # observations from a DAST scan the owner already authorized
    live_localhost = "live-localhost"  # safe probes against a disposable local test app only


class Surface(str, Enum):
    """Where in the repository a finding sits, relative to what ships."""

    production_candidate = "production_candidate"
    test = "test"
    fixture = "fixture"  # non-executable sample/teaching code
    infrastructure = "infrastructure"  # IaC / compose / deploy config
    api_spec = "api_spec"
    documentation = "documentation"
    dependency = "dependency"  # SCA findings with no source location
    unknown = "unknown"


class VerdictValue(str, Enum):
    confirmed = "confirmed"
    likely = "likely"  # strong static evidence, no runtime proof (e.g. no DAST for non-web apps); never confirmed
    not_applicable = "not_applicable"
    valid_non_security = "valid_non_security"
    needs_review = "needs_review"


class Stance(str, Enum):
    """Which way a piece of evidence pulls, for the findings it cites."""

    supports = "supports"  # the security issue is real here
    refutes = "refutes"  # the issue is not present / not applicable here
    non_security = "non_security"  # real observation, but not a security issue
    neutral = "neutral"  # context only; cannot decide anything alone


class EvidenceType(str, Enum):
    static_source = "static_source"
    deployment_boundary = "deployment_boundary"
    dependency_resolution = "dependency_resolution"
    reachability = "reachability"  # static claim - never merged with runtime
    runtime_probe = "runtime_probe"
    dast_observation = "dast_observation"  # authorized DAST scan result linked to the finding
    negative_control = "negative_control"
    advisory_precondition = "advisory_precondition"
    imported_assessment = "imported_assessment"  # carried over from a prior tool/PoC, unverified here
    model_assessment = "model_assessment"  # LLM claim with verified citations; never sufficient to confirm
    human_review = "human_review"


# --------------------------------------------------------------------------- run


class IngestionRun(_Model):
    run_id: str
    source_tool: str  # "sarif", "polaris", "semgrep", ...
    adapter: str  # e.g. "fva.adapters.sarif@0.2.0"
    raw_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_artifact_name: str
    source_repo: str | None = None
    source_commit: str | None = None  # pinned git SHA the scan refers to
    ingested_at: datetime


# ----------------------------------------------------------------------- finding


class FindingLocation(_Model):
    path: str  # repo-relative, forward slashes
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    function: str | None = None

    @field_validator("path")
    @classmethod
    def _norm(cls, v: str) -> str:
        v = v.replace("\\", "/")
        while v.startswith("./"):
            v = v[2:]
        return v


class PackageRef(_Model):
    name: str  # as the scanner named it (may be a vendor component name)
    version: str  # the version the SCANNER saw; installed version is evidence, not this
    ecosystem: str | None = None  # "npm", "pypi", "maven", ... when known
    purl: str | None = None
    advisory_id: str | None = None  # CVE / GHSA
    linked_advisory_ids: tuple[str, ...] = ()  # e.g. BDSA ids


class EndpointRef(_Model):
    """A DAST target. Host is dropped on import: only the path within the app is kept."""

    method: str = "GET"
    path: str  # e.g. "/rest/products/search"; no scheme, host, or query string
    parameter: str | None = None  # e.g. "q"
    parameter_location: Literal["query", "body", "header", "cookie", "path"] | None = None

    @field_validator("method")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("path")
    @classmethod
    def _path_only(cls, v: str) -> str:
        if "://" in v or "?" in v or not v.startswith("/"):
            raise ValueError(f"endpoint path must be an app-relative path, got {v!r}")
        return v


class Finding(_Model):
    finding_id: str
    run_id: str
    source_tool: str
    source_finding_id: str  # byte-for-byte from the scanner; never regenerated
    source_finding_id_synthesized: bool = False  # True only when the scanner gave none
    rule_id: str
    cwe: tuple[str, ...] = ()
    title: str
    description: str = ""
    severity: Severity
    finding_type: FindingType
    location: FindingLocation | None = None
    package: PackageRef | None = None
    endpoint: EndpointRef | None = None  # DAST only
    fingerprint: str | None = None  # for cross-tool de-duplication later
    scanner_metadata: dict[str, Any] = {}  # vendor extras: reachability, triage, links
    raw_evidence_ref: str  # "raw:sha256:<hex>#<json-pointer or line>"

    @field_validator("cwe")
    @classmethod
    def _cwe(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for c in v:
            if not c.startswith("CWE-") or not c[4:].isdigit():
                raise ValueError(f"bad CWE id {c!r}")
        return v


# ---------------------------------------------------------------------- evidence


class EvidenceRecord(_Model):
    evidence_id: str
    finding_ids: tuple[str, ...] = Field(min_length=1)
    evidence_type: EvidenceType
    method: str
    stance: Stance
    summary: str  # redacted BEFORE construction
    detail_ref: str | None = None
    deployment_profile_id: str | None = None  # required for runtime evidence
    collected_at: datetime
    tool_versions: dict[str, str] = {}

    @model_validator(mode="after")
    def _runtime_needs_profile(self):
        if self.evidence_type in (EvidenceType.runtime_probe, EvidenceType.negative_control,
                                  EvidenceType.dast_observation) and not self.deployment_profile_id:
            raise ValueError("runtime evidence must name its deployment_profile_id")
        return self


# ------------------------------------------------------------------ deployment


class DeploymentProfile(_Model):
    """What 'the running application' means for a set of verdicts."""

    profile_id: str
    name: str  # e.g. "local npm start"
    source_commit: str | None = None
    language_packs: tuple[str, ...] = ()  # e.g. ("node",)
    deployed_surfaces: tuple[Surface, ...] = (Surface.production_candidate, Surface.dependency)
    extra_path_rules: tuple[tuple[str, Surface], ...] = ()  # app-specific glob -> surface
    base_url: str | None = None
    entrypoints: tuple[str, ...] = ()  # repo-relative files where execution starts (server + client)


# ------------------------------------------------------------------ grouping


class LinkKind(str, Enum):
    sast_dast = "sast_dast"  # static sink observed at runtime by DAST
    sca_sast = "sca_sast"  # vulnerable package used at a SAST-reported site / call site


class FindingLink(_Model):
    """A claim that two findings describe the same flaw. Links are evidence of identity, not of exploitability."""

    link_id: str
    kind: LinkKind
    from_finding_id: str  # sast (sast_dast) or sca (sca_sast)
    to_finding_id: str  # dast (sast_dast) or sast (sca_sast)
    confidence: Literal["high", "medium", "low"]
    basis: tuple[str, ...] = Field(min_length=1)  # e.g. ("cwe", "route", "parameter")
    method: str  # e.g. "fva.correlation.runtime_link@0.1.0"


class GroupedIssue(_Model):
    issue_id: str  # deterministic from the sorted member ids
    finding_ids: tuple[str, ...] = Field(min_length=1)  # sorted, unique; never drops an original finding
    link_ids: tuple[str, ...] = ()
    primary_finding_id: str  # the finding a developer fixes (SAST sink when present)

    @model_validator(mode="after")
    def _members(self):
        if list(self.finding_ids) != sorted(set(self.finding_ids)):
            raise ValueError("finding_ids must be sorted and unique")
        if self.primary_finding_id not in self.finding_ids:
            raise ValueError("primary_finding_id must be a member")
        return self


# ----------------------------------------------------------------------- verdict


class Verdict(_Model):
    verdict_id: str
    finding_id: str
    deployment_profile_id: str
    verdict: VerdictValue
    reason_codes: tuple[str, ...] = Field(min_length=1)
    confidence: Literal["high", "medium", "low"]
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    narrative: str
    decided_at: datetime
    decided_by: dict[str, str]  # {"method": "rules|llm|human|import", "ruleset_version": ...}
    supersedes: str | None = None  # previous verdict_id for this finding+profile
