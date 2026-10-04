"""Approved, bounded localhost GET collection and verified evidence import.

Approval covers a complete plan, including its finding-specific execution oracle.
Receipts are local artifacts, not signatures or an authenticity boundary against a
person who can rewrite the receipt and approval together.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import shutil
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from fva.correlation.source_pin import pin
from fva.schemas import EvidenceRecord, EvidenceType, Stance

VERSION = "fva-runtime@1"
MAX_BYTES = 65536
IDENTITY_HEADER = "x-fva-source-sha256"


class RequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str
    method: str = "GET"


class ProbePair(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: str
    probe: RequestSpec
    control: RequestSpec
    marker: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    rationale: str = Field(min_length=1, max_length=2000)


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile_id: str
    source_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowed_urls: tuple[str, ...] = Field(min_length=1, max_length=16)
    pairs: tuple[ProbePair, ...] = Field(min_length=1, max_length=8)


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_plan(plan: Plan) -> None:
    """Validate every request before any network activity, including controls."""
    origins = set()
    for url in plan.allowed_urls:
        u = urlsplit(url)
        try:
            local = ipaddress.ip_address(u.hostname or "").is_loopback
        except ValueError:
            local = False
        if (u.scheme not in {"http", "https"} or not local or u.username is not None
                or u.password is not None or u.fragment or not u.port or any(c.isspace() for c in url)):
            raise ValueError("only explicit loopback IP URLs with a port and no credentials/fragments are allowed")
        origins.add((u.scheme, u.hostname, u.port))
    if len(origins) != 1 or len(set(plan.allowed_urls)) != len(plan.allowed_urls):
        raise ValueError("allowlist must contain unique URLs on one origin")
    if len({p.finding_id for p in plan.pairs}) != len(plan.pairs):
        raise ValueError("one probe/control pair per finding is required")
    for pair in plan.pairs:
        for request in (pair.control, pair.probe):
            if request.method != "GET" or request.url not in plan.allowed_urls:
                raise ValueError("non-GET or out-of-allowlist request rejected")
            if pair.marker in unquote(request.url):
                raise ValueError("execution marker must not be present in either request")
        if pair.control.url == pair.probe.url:
            raise ValueError("probe and control must differ")


def validate_approval(plan: Plan, approval: dict) -> None:
    if (approval.get("plan_sha256") != digest(plan.model_dump(mode="json"))
            or approval.get("decision") != "approved" or not approval.get("approved_by", "").strip()
            or not approval.get("approved_at")):
        raise ValueError("an explicit approval receipt for this exact plan is required")
    datetime.fromisoformat(approval["approved_at"].replace("Z", "+00:00"))


def bind_run(plan: Plan, run: Path) -> None:
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    if (summary.get("profile") != plan.profile_id
            or summary.get("source_content_sha256") != plan.source_content_sha256
            or file_digest(run / "findings.jsonl") != plan.findings_sha256):
        raise ValueError("plan does not match the run's profile, source and findings")
    findings = {r["finding_id"]: r for r in read_rows(run / "findings.jsonl")}
    for pair in plan.pairs:
        row = findings.get(pair.finding_id)
        # This version has only an approved code-execution marker oracle.
        if (not row or "CWE-94" not in row.get("cwe", []) or row.get("disposition") != "assess"
                or row.get("finding_type") != "sast"):
            raise ValueError("execution oracle requires an assessable SAST CWE-94 finding")


def fetch(spec: RequestSpec) -> dict:
    """No redirects, environment proxies, cookies, authentication or request bodies."""
    u = urlsplit(spec.url)
    connection_type = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(u.hostname, u.port, timeout=3)
    timer = None
    expired = threading.Event()
    try:
        connection.connect()
        transport = connection.sock

        def stop():
            expired.set()
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        # A socket idle timeout alone permits endless trickle responses. Stop total I/O too.
        timer = threading.Timer(3, stop)
        timer.daemon = True
        timer.start()
        connection.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""),
                           headers={"Accept": "text/plain", "Connection": "close"})
        with connection.getresponse() as response:
            body = response.read(MAX_BYTES + 1)
            if expired.is_set():
                raise TimeoutError("response deadline exceeded")
            return {"url": spec.url, "method": "GET", "status": response.status,
                    "source_content_sha256": response.headers.get(IDENTITY_HEADER),
                    "body_b64": base64.b64encode(body[:MAX_BYTES]).decode(),
                    "truncated": len(body) > MAX_BYTES}
    except (http.client.HTTPException, TimeoutError, OSError):
        return {"url": spec.url, "method": "GET", "error": "transport failure"}
    finally:
        if timer:
            timer.cancel()
        connection.close()


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def collect(run: Path, source: Path, plan_path: Path, approval_path: Path, out: Path) -> dict:
    plan = Plan.model_validate_json(plan_path.read_text(encoding="utf-8"))
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    validate_plan(plan)
    validate_approval(plan, approval)
    bind_run(plan, run)
    before = pin(source)
    if (before.content_sha256 != plan.source_content_sha256 or before.vcs_dirty is True
            or (before.vcs_commit is not None and before.vcs_dirty is not False)):
        raise ValueError("source changed or is dirty; no probes sent")
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"producer": VERSION, "plan": plan.model_dump(mode="json"), "approval": approval,
               "collected_at": datetime.now(timezone.utc).isoformat(),
               "source_before": before.content_sha256, "observations": []}
    for pair in plan.pairs:
        receipt["observations"].append({"finding_id": pair.finding_id,
                                        "control": fetch(pair.control), "probe": fetch(pair.probe)})
        write_json(out / "receipt.json", receipt)
    after = pin(source)
    receipt["source_after"] = after.content_sha256
    write_json(out / "receipt.json", receipt)
    return {"pairs": len(plan.pairs), "requests": len(plan.pairs) * 2}


def evidence_from_receipt(receipt: dict, run: Path) -> list[EvidenceRecord]:
    """Recompute evidence from approved requests and retained bytes, never typed assertions."""
    if receipt["producer"] != VERSION:
        raise ValueError("unknown runtime producer")
    plan = Plan.model_validate(receipt["plan"])
    validate_plan(plan)
    validate_approval(plan, receipt["approval"])
    bind_run(plan, run)
    if not (receipt["source_before"] == receipt["source_after"] == plan.source_content_sha256):
        raise ValueError("source changed during collection")
    if len(receipt["observations"]) != len(plan.pairs):
        raise ValueError("incomplete receipt")
    records = []
    receipt_hash = digest(receipt)
    for n, (pair, observed) in enumerate(zip(plan.pairs, receipt["observations"])):
        if observed["finding_id"] != pair.finding_id:
            raise ValueError("receipt finding mismatch")
        bodies = []
        valid = True
        for name, spec in (("control", pair.control), ("probe", pair.probe)):
            response = observed[name]
            if response["url"] != spec.url or response["method"] != "GET":
                raise ValueError("receipt request mismatch")
            raw = base64.b64decode(response.get("body_b64", ""), validate=True)
            if len(raw) > MAX_BYTES:
                raise ValueError("response exceeds collection limit")
            bodies.append(raw)
            valid &= (response.get("status") == 200 and not response.get("error")
                      and response.get("truncated") is False
                      and response.get("source_content_sha256") == plan.source_content_sha256)
        supports = valid and pair.marker.encode() not in bodies[0] and pair.marker.encode() in bodies[1]
        probe_id = f"runtime:{receipt_hash}:{n}:probe"
        for name, kind, stance in (("probe", EvidenceType.runtime_probe,
                                    Stance.supports if supports else Stance.neutral),
                                   ("control", EvidenceType.negative_control, Stance.neutral)):
            records.append(EvidenceRecord(
                evidence_id=probe_id if name == "probe" else f"runtime:{receipt_hash}:{n}:control",
                finding_ids=(pair.finding_id,), evidence_type=kind, method=VERSION, stance=stance,
                summary="Approved execution marker observed with control and source binding." if supports
                        else "Probe/control observations do not establish execution; keep unresolved.",
                detail_ref=f"raw:sha256:{receipt_hash}#/observations/{n}/{name}",
                deployment_profile_id=plan.profile_id, collected_at=receipt["collected_at"],
                tool_versions={"collector": VERSION, "receipt_sha256": receipt_hash,
                               **({"control_for": probe_id} if name == "control" else {})}))
    return records


def import_collection(run: Path, collection: Path, out: Path) -> dict:
    receipt = json.loads((collection / "receipt.json").read_text(encoding="utf-8"))
    records = evidence_from_receipt(receipt, run)
    out.mkdir(parents=True, exist_ok=False)
    for name in ("findings.jsonl", "evidence.jsonl", "summary.json"):
        shutil.copyfile(run / name, out / name)
    (out / "runtime-receipt.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with (out / "evidence.jsonl").open("a", encoding="utf-8") as stream:
        # Ensure an imported legacy file without a trailing newline remains valid JSONL.
        stream.write("\n" + "\n".join(r.model_dump_json() for r in records) + "\n")
    from fva.export.worksheet import write
    result = write(out)
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    summary.update({"verdicts": result["verdicts"],
                    "runtime_collection": {"producer": VERSION, "receipt_sha256": digest(receipt)}})
    write_json(out / "summary.json", summary)
    return result


def verified_ids(run: Path, evidence: list[EvidenceRecord]) -> frozenset[str]:
    receipt_path = run / "runtime-receipt.json"
    if not receipt_path.exists():
        return frozenset()
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if file_digest(receipt_path) != digest(receipt):
            return frozenset()
        expected = evidence_from_receipt(receipt, run)
        actual = {e.evidence_id: e for e in evidence}
        if len(actual) != len(evidence) or any(actual.get(e.evidence_id) != e for e in expected):
            return frozenset()
        return frozenset(e.evidence_id for e in expected)
    except (ValueError, KeyError, TypeError, OSError):
        return frozenset()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fva runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("approval-template", help="create an unapproved receipt; sends no requests")
    prepare.add_argument("plan", type=Path)
    prepare.add_argument("--out", type=Path, required=True)
    collector = commands.add_parser("collect", help="run an approved localhost GET plan")
    collector.add_argument("run", type=Path)
    collector.add_argument("--source", type=Path, required=True)
    collector.add_argument("--plan", type=Path, required=True)
    collector.add_argument("--approval", type=Path, required=True)
    collector.add_argument("--out", type=Path, required=True)
    importer = commands.add_parser("import", help="verify a collection into a new run; does not send requests")
    importer.add_argument("run", type=Path)
    importer.add_argument("collection", type=Path)
    importer.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "approval-template":
        plan = Plan.model_validate_json(args.plan.read_text(encoding="utf-8"))
        validate_plan(plan)
        # Never overwrite an existing approval.
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump({"plan_sha256": digest(plan.model_dump(mode="json")), "decision": "pending",
                       "approved_by": "", "approved_at": ""}, stream, indent=2)
        result = {"status": "approval required; no requests sent"}
    elif args.command == "collect":
        result = collect(args.run, args.source, args.plan, args.approval, args.out)
    else:
        result = import_collection(args.run, args.collection, args.out)
    print(json.dumps(result))
    return result
