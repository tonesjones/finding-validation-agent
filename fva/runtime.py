"""Approved, bounded localhost GET collection and verified evidence import.

Approval covers a complete plan, including its finding-specific oracle.
Receipts are local artifacts, not signatures or an authenticity boundary against a
person who can rewrite the receipt and approval together.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import re
import shutil
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from fva.correlation.runtime_link import build_route_map
from fva.correlation.source_pin import iter_files, pin
from fva.schemas import EvidenceRecord, EvidenceType, Stance

VERSION = "fva-runtime@2"
MAX_BYTES = 65536
IDENTITY_HEADER = "x-fva-source-sha256"
# Headers a framework's default app sends without any literal in the source: (name, value) -> module the
# finding's file must import.
FRAMEWORK_HEADERS = {("x-powered-by", "Express"): "express"}


class RequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str
    method: str = "GET"


class ProbePair(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: str
    probe: RequestSpec
    control: RequestSpec
    marker: str | None = Field(default=None, min_length=16, max_length=128,
                               pattern=r"^[A-Za-z0-9_-]+$", exclude_if=lambda v: v is None)
    rationale: str = Field(min_length=1, max_length=2000)
    oracle: str = Field(default="execution_marker", exclude_if=lambda v: v == "execution_marker")
    header_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]+$",
                                     exclude_if=lambda v: v is None)
    expected_value: str | None = Field(default=None, min_length=1, max_length=1000,
                                        exclude_if=lambda v: v is None)
    call_site: str | None = Field(default=None, pattern=r"^[^:\r\n]+:[1-9][0-9]*$",
                                   exclude_if=lambda v: v is None)


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile_id: str
    source_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowed_urls: tuple[str, ...] = Field(min_length=1, max_length=16)
    pairs: tuple[ProbePair, ...] = Field(min_length=1, max_length=8)
    source_root: str | None = Field(default=None, exclude_if=lambda v: v is None)
    entrypoints: tuple[str, ...] = Field(default=(), exclude_if=lambda v: not v)


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contains_marker(url: str, marker: str) -> bool:
    """Inspect common reflection encodings, recursively and with bounded work."""
    pending, seen = [url], set()
    while pending:
        value = pending.pop()
        if value in seen:
            continue
        seen.add(value)
        if len(seen) > 128 or len(value) > 8192:
            raise ValueError("request encoding exceeds inspection limits")
        if marker.casefold() in value.casefold():
            return True
        decoded = unquote(value)
        if decoded != value:
            pending.append(decoded)
        tokens = re.split(r"[&?=;\s]+", value)
        tokens += [segment for token in tokens for segment in token.split("/")]
        for token in tokens:
            if len(token) < 4:
                continue
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
                try:
                    pending.append(bytes.fromhex(token).decode("utf-8"))
                except UnicodeDecodeError:
                    pass
            if re.fullmatch(r"[A-Za-z0-9+_-]+", token):
                try:
                    pending.append(base64.b64decode(token + "=" * (-len(token) % 4),
                                                   altchars=b"-_", validate=True).decode("utf-8"))
                except (binascii.Error, UnicodeDecodeError):
                    pass
    return False


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
        if pair.oracle not in {"execution_marker", "header_disclosure", "sca_marker"}:
            raise ValueError("unknown runtime oracle")
        if pair.oracle == "header_disclosure":
            if (pair.marker is not None or pair.call_site is not None or not pair.header_name
                    or pair.header_name.lower() == IDENTITY_HEADER or not pair.expected_value
                    or any(ord(c) < 32 or ord(c) == 127 for c in pair.expected_value)):
                raise ValueError("header oracle requires one safe name and exact value")
        elif (not pair.marker or pair.header_name is not None or pair.expected_value is not None
              or (pair.oracle == "execution_marker" and pair.call_site is not None)
              or (pair.oracle == "sca_marker" and not pair.call_site)):
            raise ValueError("marker oracle fields do not match the selected oracle")
        if pair.oracle != "execution_marker" and not plan.source_root:
            raise ValueError("new oracles require a pinned source root")
        for request in (pair.control, pair.probe):
            if request.method != "GET" or request.url not in plan.allowed_urls:
                raise ValueError("non-GET or out-of-allowlist request rejected")
            if pair.marker and contains_marker(request.url, pair.marker):
                raise ValueError("execution marker must not be present or encoded in either request")
        if pair.control.url == pair.probe.url:
            raise ValueError("probe and control must differ")


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO string")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("approval and collection timestamps must include a timezone")
    return result


def validate_approval(plan: Plan, approval: dict, *, collected_at: datetime | None = None) -> None:
    plan_hash = digest(plan.model_dump(mode="json"))
    name = approval.get("approved_by")
    if (approval.get("plan_sha256") != plan_hash
            or approval.get("decision") != "approved" or not isinstance(name, str) or not name.strip()
            or approval.get("method") != "interactive-tty"
            or approval.get("acknowledged_plan_prefix") != plan_hash[:12]
            or not approval.get("approved_at")):
        raise ValueError("interactive approval for this exact plan is required")
    if timestamp(approval["approved_at"]) > (collected_at or datetime.now(timezone.utc)):
        raise ValueError("approval must precede collection")


def approve(plan_path: Path, out: Path) -> dict:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("runtime approve requires an interactive TTY; redirected input is rejected")
    plan = Plan.model_validate_json(plan_path.read_text(encoding="utf-8"))
    validate_plan(plan)
    plan_hash = digest(plan.model_dump(mode="json"))
    # JSON escaping prevents a plan's text from controlling the terminal display.
    print(json.dumps(plan.model_dump(mode="json"), indent=2, ensure_ascii=True))
    print("Review every URL, marker and rationale above. This authorizes the exact GET plan.")
    name = input("Your name: ").strip()
    acknowledgement = input(f"Type plan hash prefix {plan_hash[:12]} to approve: ").strip()
    if not name or acknowledgement != plan_hash[:12]:
        raise ValueError("approval cancelled; name and exact hash prefix are required")
    receipt = {"plan_sha256": plan_hash, "decision": "approved", "approved_by": name,
               "approved_at": datetime.now(timezone.utc).isoformat(), "method": "interactive-tty",
               "acknowledged_plan_prefix": acknowledgement}
    with out.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    return {"status": "approved", "plan_sha256": plan_hash}


def bind_run(plan: Plan, run: Path, *, check_source: bool = True) -> None:
    """Plan <-> run binding. Source checks run at collection and import; later receipt verification skips them so
    an edited checkout cannot silently change an already imported result."""
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    if (summary.get("profile") != plan.profile_id
            or summary.get("source_content_sha256") != plan.source_content_sha256
            or file_digest(run / "findings.jsonl") != plan.findings_sha256):
        raise ValueError("plan does not match the run's profile, source and findings")
    findings = {r["finding_id"]: r for r in read_rows(run / "findings.jsonl")}
    root = Path(plan.source_root) if plan.source_root and check_source else None
    files = {name for name, _ in iter_files(root)} if root else set()
    if root and pin(root).content_sha256 != plan.source_content_sha256:
        raise ValueError("pinned source root does not match the plan")
    for pair in plan.pairs:
        row = findings.get(pair.finding_id)
        if not row or row.get("disposition") != "assess":
            raise ValueError("oracle requires an assessable finding")
        if pair.oracle == "execution_marker" and ("CWE-94" not in row.get("cwe", [])
                                                   or row.get("finding_type") != "sast"):
            raise ValueError("execution oracle requires an assessable SAST CWE-94 finding")
        if pair.oracle == "header_disclosure":
            if row.get("finding_type") != "sast" or not {"CWE-200", "CWE-201"} & set(row.get("cwe", [])):
                raise ValueError("header oracle requires an assessable SAST CWE-200/201 finding")
            path, line = row.get("path"), row.get("line")
            if root is None:
                continue
            if path not in files or not isinstance(line, int) or line < 1:
                raise ValueError("header finding has no pinned source location")
            text = (root / path).read_text(encoding="utf-8", errors="replace")
            module = FRAMEWORK_HEADERS.get((pair.header_name.lower(), pair.expected_value))
            imported = module and re.search(rf"""(?:\bfrom\s*|\brequire\s*\(\s*)(['"]){re.escape(module)}\1""", text)
            if not imported and pair.expected_value not in "\n".join(text.splitlines()[max(0, line - 16):line + 15]):
                raise ValueError("expected header value is absent near the finding line")
        if pair.oracle == "sca_marker":
            if row.get("finding_type") != "sca":
                raise ValueError("SCA marker oracle requires an assessable SCA finding")
            sites = set()
            for record in read_rows(run / "evidence.jsonl"):
                if (record.get("evidence_type") == "static_source"
                        and record.get("method") == "advisory_call_site:called"
                        and pair.finding_id in record.get("finding_ids", [])):
                    sites.update(part.rsplit(" at ", 1)[-1] for part in
                                 record.get("summary", "").split(": ", 1)[-1].split("; "))
            if pair.call_site not in sites:
                raise ValueError("SCA call site is absent from called evidence")
            path = pair.call_site.rsplit(":", 1)[0]
            if root is None:
                continue
            if not plan.entrypoints or not set(plan.entrypoints) <= files:
                raise ValueError("SCA route entrypoints are absent from pinned source")
            routes = build_route_map(root, sorted(files), plan.entrypoints)
            route = urlsplit(pair.probe.url).path or "/"
            if path not in routes.get(("GET", route), set()) | routes.get(("ALL", route), set()):
                raise ValueError("probe route does not reach the SCA call site file")


def fetch(spec: RequestSpec, header_names: tuple[str, ...] = ()) -> dict:
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
            ids = response.headers.get_all(IDENTITY_HEADER, [])
            captured = {}
            for name in header_names:
                values = response.headers.get_all(name, [])
                captured[name.lower()] = values[0] if len(values) == 1 else None
            return {"url": spec.url, "method": "GET", "status": response.status,
                    "source_content_sha256": ids[0] if len(ids) == 1 else None,
                    **({"headers": captured} if header_names else {}),
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
    if plan.source_root and Path(plan.source_root).resolve() != source.resolve():
        raise ValueError("approved source root does not match collection source")
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
        names = (pair.header_name,) if pair.oracle == "header_disclosure" else ()
        receipt["observations"].append({"finding_id": pair.finding_id,
                                        "control": fetch(pair.control, names) if names else fetch(pair.control),
                                        "probe": fetch(pair.probe, names) if names else fetch(pair.probe)})
        write_json(out / "receipt.json", receipt)
    after = pin(source)
    receipt["source_after"] = after.content_sha256
    write_json(out / "receipt.json", receipt)
    return {"pairs": len(plan.pairs), "requests": len(plan.pairs) * 2}


def evidence_from_receipt(receipt: dict, run: Path, *, check_source: bool = True) -> list[EvidenceRecord]:
    """Recompute evidence from approved requests and retained bytes, never typed assertions."""
    if receipt["producer"] != VERSION:
        raise ValueError("unknown runtime producer")
    plan = Plan.model_validate(receipt["plan"])
    validate_plan(plan)
    validate_approval(plan, receipt["approval"], collected_at=timestamp(receipt["collected_at"]))
    bind_run(plan, run, check_source=check_source)
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
            if pair.oracle == "header_disclosure":
                captured = response.get("headers", {})
                if not isinstance(captured, dict) or set(captured) - {pair.header_name.lower()}:
                    raise ValueError("receipt contains an unapproved header")
            raw = base64.b64decode(response.get("body_b64", ""), validate=True)
            if len(raw) > MAX_BYTES:
                raise ValueError("response exceeds collection limit")
            bodies.append(raw)
            valid &= (response.get("status") == 200 and not response.get("error")
                      and response.get("truncated") is False
                      and response.get("source_content_sha256") == plan.source_content_sha256)
        if pair.oracle == "header_disclosure":
            supports = valid and observed["probe"].get("headers", {}).get(pair.header_name.lower()) == pair.expected_value
            summary = "Approved exact header observed with control and source binding."
            neutral_summary = "Probe/control observations do not establish header disclosure; keep unresolved."
        else:
            supports = valid and pair.marker.encode() not in bodies[0] and pair.marker.encode() in bodies[1]
            summary = ("Approved SCA marker observed with control and source binding." if pair.oracle == "sca_marker"
                       else "Approved execution marker observed with control and source binding.")
            neutral_summary = ("Probe/control observations do not establish SCA marker execution; keep unresolved."
                               if pair.oracle == "sca_marker" else
                               "Probe/control observations do not establish execution; keep unresolved.")
        probe_id = f"runtime:{receipt_hash}:{n}:probe"
        for name, kind, stance in (("probe", EvidenceType.runtime_probe,
                                    Stance.supports if supports else Stance.neutral),
                                   ("control", EvidenceType.negative_control, Stance.neutral)):
            records.append(EvidenceRecord(
                evidence_id=probe_id if name == "probe" else f"runtime:{receipt_hash}:{n}:control",
                finding_ids=(pair.finding_id,), evidence_type=kind, method=VERSION, stance=stance,
                summary=summary if supports
                        else neutral_summary,
                detail_ref=f"raw:sha256:{receipt_hash}#/observations/{n}/{name}",
                deployment_profile_id=plan.profile_id, collected_at=receipt["collected_at"],
                tool_versions={"collector": VERSION, "receipt_sha256": receipt_hash,
                               **({"control_for": probe_id} if name == "control" else {})}))
    return records


def import_collection(run: Path, collection: Path, out: Path) -> dict:
    if (run / "runtime-receipt.json").exists():
        raise ValueError("one collection per derived run; import each collection from the original base run")
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


def verify_runtime(run: Path, evidence: list[EvidenceRecord]) -> tuple[frozenset[str], str | None]:
    receipt_path = run / "runtime-receipt.json"
    if not receipt_path.exists():
        warning = "Runtime receipt missing; runtime evidence remains unresolved." if any(
            e.evidence_type in {EvidenceType.runtime_probe, EvidenceType.negative_control} for e in evidence) else None
        return frozenset(), warning
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if file_digest(receipt_path) != digest(receipt):
            raise ValueError("receipt bytes do not match their content hash")
        expected = evidence_from_receipt(receipt, run, check_source=False)
        actual = {e.evidence_id: e for e in evidence}
        if len(actual) != len(evidence) or any(actual.get(e.evidence_id) != e for e in expected):
            raise ValueError("stored evidence does not match the recomputed receipt evidence")
        return frozenset(e.evidence_id for e in expected), None
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
        # Do not include exception values: malformed artifacts may contain private text.
        reason = {
            "receipt bytes do not match their content hash": "receipt byte integrity check failed",
            "stored evidence does not match the recomputed receipt evidence": "stored evidence mismatch",
            "approval must precede collection": "approval is dated after collection",
            "interactive approval for this exact plan is required": "interactive plan approval is missing or mismatched",
            "plan does not match the run's profile, source and findings": "run profile, source or findings mismatch",
            "source changed during collection": "source changed during collection",
            "unknown runtime producer": "unsupported collector version",
            "incomplete receipt": "receipt is incomplete",
            "receipt request mismatch": "observed request does not match the approved plan",
        }.get(str(exc), "receipt verification failed because its structure or plan is invalid")
        return frozenset(), f"Runtime {reason}; evidence remains unresolved."


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fva runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("approval-template", help="create an unapproved receipt; sends no requests")
    prepare.add_argument("plan", type=Path)
    prepare.add_argument("--out", type=Path, required=True)
    approval_command = commands.add_parser("approve", help="review and approve a plan in an interactive terminal")
    approval_command.add_argument("plan", type=Path)
    approval_command.add_argument("--out", type=Path, required=True)
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
    elif args.command == "approve":
        result = approve(args.plan, args.out)
    elif args.command == "collect":
        result = collect(args.run, args.source, args.plan, args.approval, args.out)
    else:
        result = import_collection(args.run, args.collection, args.out)
    print(json.dumps(result))
    return result
