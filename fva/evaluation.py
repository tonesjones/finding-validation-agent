"""Source preflight and frozen, paired evaluation. Gold is read only by score."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from fva.__main__ import PROFILES, load_profile
from fva.correlation import reachability, runtime_link
from fva.correlation.source_pin import iter_files, pin
from fva.langpacks import REGISTRY
from fva.surface import is_deployed, match_rule


def read_rows(path):
    return [json.loads(s) for s in Path(path).read_text(encoding="utf-8").splitlines() if s.strip()]


def seal(out: Path, name: str, files: list[Path]):
    hashes = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    write_json(out / name, {"files": hashes, "sha256": digest(hashes)})


def verify_seal(out: Path, name: str):
    manifest = json.loads((out / name).read_text(encoding="utf-8"))
    if manifest["sha256"] != digest(manifest["files"]):
        raise ValueError("manifest hash mismatch")
    for rel, sha in manifest["files"].items():
        if not (out / rel).resolve().is_relative_to(out.resolve()):
            raise ValueError("manifest path escapes run")
        if hashlib.sha256((out / rel).read_bytes()).hexdigest() != sha:
            raise ValueError(f"frozen artifact changed: {rel}")
    return manifest


def prepare_cases(source, profile, out, report, *, findings_specs=(), canonical_paths=(), approved=None,
                  lockfile=None):
    from fva import pipeline
    from fva.correlation import dast_evidence, locate
    from fva.discovery import freeze_source
    from fva.reasoning import assessor
    from fva.redact import redact, redact_value
    from fva.schemas import Finding, FindingType, RuntimeMode

    findings, exports = [], {}
    import glob
    for spec in findings_specs:
        paths = sorted(glob.glob(spec)) or [spec]
        for path in paths:
            exports[str(Path(path).resolve())] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            types_file = Path(path).parent / "types.json"
            if types_file.exists():
                exports[str(types_file.resolve())] = hashlib.sha256(types_file.read_bytes()).hexdigest()
        findings.extend(pipeline.load_findings(spec))
    for path in canonical_paths:
        exports[str(Path(path).resolve())] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        findings.extend(Finding.model_validate(row) for row in read_rows(path))
    by_id = {}
    for f in findings:
        if f.finding_id in by_id and f != by_id[f.finding_id]:
            raise ValueError(f"conflicting finding id: {f.finding_id}")
        by_id[f.finding_id] = f
    findings = [f.model_copy(update={"title": redact(f.title), "description": redact(f.description),
                                    "scanner_metadata": redact_value(f.scanner_metadata)}) for f in by_id.values()]
    by_id = {f.finding_id: f for f in findings}
    snapshot, contents, _ = freeze_source(source, profile, out)
    if snapshot.content_sha256 != report["snapshot"]["content_sha256"]:
        raise ValueError("source changed since preflight")
    for f in findings:
        discovered_sha = f.scanner_metadata.get("source_sha256")
        if f.source_tool == "llm-discovery" and discovered_sha != snapshot.content_sha256:
            raise ValueError("discovery/source pin mismatch")
    frozen = out / "source"
    files = list(contents)
    idx = locate.SourceIndex(frozen, files)
    graph = reachability.build_graph(frozen, files, profile)
    static = [f for f in findings if f.finding_type is not FindingType.dast]
    dast = [f for f in findings if f.finding_type is FindingType.dast]
    batch = pipeline.prepare(static, frozen, profile, lockfile, snapshot.content_sha256, idx, graph)
    routes = runtime_link.build_route_map(frozen, files, profile.entrypoints)
    links = runtime_link.link_all([f for f in static if f.finding_type is FindingType.sast], dast, routes,
                                 {rel: idx.lines(rel) for rel in files})
    scope = {"source_sha256": snapshot.content_sha256, "profile_sha256": report["profile_sha256"],
             "exports": exports}
    approvals = json.loads(Path(approved).read_text(encoding="utf-8")) if approved else None
    high_ids = {l.link_id for l in links if l.confidence == "high"}
    approved_ids = set()
    if approvals:
        if approvals.get("scope") != scope:
            raise ValueError("link approval scope mismatch: source/profile/export hashes changed")
        for row in approvals.get("links", []):
            if row["link_id"] not in high_ids:
                raise ValueError("approval names an absent or non-high-confidence link")
            if row.get("decision") == "approved":
                if not row.get("reviewer") or not row.get("rationale"):
                    raise ValueError("approved link needs reviewer and rationale")
                approved_ids.add(row["link_id"])
    review = []
    runtime = {}
    for link in links:
        a, b = by_id[link.from_finding_id], by_id[link.to_finding_id]
        included = link.link_id in approved_ids and report["dast_ready"]
        review.append({"link": link.model_dump(mode="json"), "static": a.model_dump(mode="json"),
                       "dast": b.model_dump(mode="json"), "included": included,
                       "exclusion_reason": None if included else "route preflight blocked" if not report["dast_ready"]
                       else "human link approval required" if link.confidence == "high" else "confidence below high"})
        if included:
            ev = dast_evidence.to_evidence(link, profile_id=profile.profile_id, mode=RuntimeMode.dast_evidence)
            observation = redact(f"DAST observation: {b.description}\n{json.dumps(redact_value(b.scanner_metadata))}")
            ev = ev.model_copy(update={"summary": ev.summary + "\n" + observation,
                                      "detail_ref": link.link_id})
            runtime.setdefault(a.finding_id, []).append(ev)
    write_json(out / "link-review.json", {"scope": scope, "links": review})
    write_json(out / "approval-template.json", {"scope": scope,
               "links": [{"link_id": l.link_id, "decision": "pending", "reviewer": "", "rationale": ""}
                         for l in links if l.confidence == "high"]})
    # Exact static location + CWE, or identical package advisory. Preserve every report and origin.
    groups = {}
    for f in static:
        key = ("sast", f.location.path, f.location.start_line, tuple(sorted(f.cwe))) \
            if f.finding_type is FindingType.sast and f.location and f.location.start_line and f.cwe \
            else pipeline.cluster_key(f) + (f.finding_id,)
        if f.finding_type is FindingType.sca and f.package:
            key = pipeline.cluster_key(f)
        groups.setdefault(key, []).append(f)
    packets = []
    for members in groups.values():
        members.sort(key=lambda f: (f.source_tool == "llm-discovery", f.finding_id))
        lead = members[0]
        case_id = "case:" + digest(sorted(f.finding_id for f in members))
        evs = [ev for f in members for ev in batch.pre_evidence[f.finding_id] + runtime.get(f.finding_id, [])]
        evs = list({e.evidence_id: e for e in evs}.values())
        sites = batch.sites.get(pipeline.cluster_key(lead), [])
        prompt = redact(assessor.build_prompt(lead, idx, evs, sites))
        row = {"finding_id": lead.finding_id, "finding_type": lead.finding_type.value,
               "disposition": batch.disposition[lead.finding_id]}
        packet = {"case_id": case_id, "finding": lead.model_dump(mode="json"), "row": row,
                  "original_findings": [f.model_dump(mode="json") for f in members],
                  "evidence": [e.model_dump(mode="json") for e in evs], "sites": sites,
                  "prompt": prompt, "system": assessor.SYSTEM, "prompt_version": assessor.PROMPT_VERSION,
                  "approved_link_ids": sorted({e.detail_ref for e in evs if e.detail_ref in approved_ids}),
                  "source_sha256": snapshot.content_sha256, "profile_sha256": report["profile_sha256"]}
        packet["packet_sha256"] = digest(packet)
        packets.append(packet)
    (out / "cases.jsonl").write_text("".join(json.dumps(p) + "\n" for p in packets), encoding="utf-8")
    linked_dast = {l.to_finding_id for l in links}
    write_json(out / "coverage.json", {"static_reports": len(static), "static_cases": len(packets),
               "dast_reports": len(dast), "dast_only": [f.model_dump(mode="json") for f in dast
                                                         if f.finding_id not in linked_dast],
               "scanner_status": "exported findings only; pending scans are unknown",
               "discovery_vs_validation": "separate; verified discovery coverage awaits human adjudication"})
    write_json(out / "assessment.schema.json", json.loads(Path(assessor.__file__).with_name(
        "assessment.schema.json").read_text(encoding="utf-8")))
    if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha for path, sha in exports.items()):
        raise ValueError("input export changed during preparation")
    seal(out, "prepared.json", [p for p in out.rglob("*") if p.is_file()])
    return {"cases": len(packets), "approved_links": len(approved_ids), "out": str(out.resolve())}


def raw_verdict(raw):
    from fva.discovery import Citation
    from fva.schemas import Stance
    if not isinstance(raw, dict) or not isinstance(raw.get("claims"), list) \
            or raw.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError("malformed assessment response")
    stances = set()
    for claim in raw["claims"]:
        if not isinstance(claim, dict) or not isinstance(claim.get("statement"), str) \
                or not isinstance(claim.get("citations"), list):
            raise ValueError("malformed claim")
        stances.add(Stance(claim["stance"]).value)
        for citation in claim["citations"]:
            Citation.model_validate(citation)
    stances.discard("neutral")
    stance = next(iter(stances)) if len(stances) == 1 else "neutral"
    return {"supports": "likely", "refutes": "not_applicable", "non_security": "valid_non_security",
            "neutral": "needs_review"}[stance]


def run_cases(prepared: Path, out: Path, *, smoke=False, smoke_run=None, client=None,
              labels_receipt: Path | None = None):
    from fva.correlation.locate import SourceIndex
    from fva.discovery import FIXED_MODEL, checked_call
    from fva.reasoning import assessor
    from fva.reasoning.model import CodexCliClient, ScriptedClient
    from fva.schemas import EvidenceRecord, Finding
    from fva.verdicts import suggest_verdict, check_suggestion

    manifest = verify_seal(prepared, "prepared.json")
    cases = read_rows(prepared / "cases.jsonl")
    if not smoke and cases:
        if not smoke_run:
            raise ValueError("batch requires --smoke-run from a successful smoke on these packets")
        verify_seal(Path(smoke_run), "outputs.json")
        receipt = json.loads((Path(smoke_run) / "smoke.json").read_text(encoding="utf-8"))
        if receipt != {"prepared_sha256": manifest["sha256"], "observed_model": FIXED_MODEL}:
            raise ValueError("smoke receipt mismatch")
    if cases:
        if not labels_receipt:
            raise ValueError("labels must be frozen before responses; supply --labels-receipt")
        labels = json.loads(labels_receipt.read_text(encoding="utf-8"))
        if labels.get("prepared_sha256") != manifest["sha256"] or not labels.get("reviewer") \
                or not isinstance(labels.get("gold_sha256"), str) or len(labels["gold_sha256"]) != 64:
            raise ValueError("labels receipt must name reviewer, prepared hash and private gold SHA256")
        if not smoke:
            smoke_meta = json.loads((Path(smoke_run) / "run.json").read_text(encoding="utf-8"))
            if smoke_meta["labels_receipt"] != labels:
                raise ValueError("labels receipt differs from smoke; labels must be frozen before any responses")
    else:
        labels = None
    if out.exists() and any(out.iterdir()):
        raise ValueError("run output must be empty; existing responses cannot be overwritten")
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "run.json", {"prepared_sha256": manifest["sha256"], "smoke": smoke,
                                  "labels_receipt": labels, "requested_model": FIXED_MODEL})
    if cases:
        client = client or CodexCliClient(model=FIXED_MODEL, schema_file=(prepared / "assessment.schema.json").resolve(),
                                          audit=True)
    source_files = [p.relative_to(prepared / "source").as_posix() for p in (prepared / "source").rglob("*") if p.is_file()]
    idx = SourceIndex(prepared / "source", source_files)
    results, human = [], []
    start = 0
    if not smoke and cases:
        import shutil
        results = read_rows(Path(smoke_run) / "results.jsonl")
        if len(results) != 1 or results[0]["case_id"] != cases[0]["case_id"]:
            raise ValueError("smoke response does not match first prepared case")
        human = json.loads((Path(smoke_run) / "human-review.json").read_text(encoding="utf-8"))
        shutil.copytree(Path(smoke_run) / "case-0000", out / "case-0000")
        start = 1
    for number, packet in enumerate(cases[:1] if smoke else cases[start:], start=start):
        if packet["packet_sha256"] != digest({k: v for k, v in packet.items() if k != "packet_sha256"}):
            raise ValueError("case packet hash mismatch")
        call_dir = out / f"case-{number:04d}"
        call_dir.mkdir()
        finding = Finding.model_validate(packet["finding"])
        evs = [EvidenceRecord.model_validate(e) for e in packet["evidence"]]
        rules = suggest_verdict(packet["row"], evs)[0].value
        row = {"case_id": packet["case_id"], "packet_sha256": packet["packet_sha256"], "rules_only": rules,
               "approved_link_ids": packet["approved_link_ids"], "processing_failure": None}
        try:
            text, meta = checked_call(client, packet["system"], packet["prompt"], call_dir)
            raw = json.loads(text)
            llm = raw_verdict(raw)
            replay = ScriptedClient([text], model_id=f"codex-cli:{FIXED_MODEL}")
            replay.last_reported_model = meta["observed_model"]
            replay.last_tokens = getattr(client, "last_tokens", None)
            res = assessor.assess(finding, idx, replay, source_content_sha256=packet["source_sha256"],
                                  profile_id=next((e.deployment_profile_id for e in evs if e.deployment_profile_id),
                                                  "evaluation"), evidence=evs, sites=packet["sites"], cache_dir=None)
            hybrid_evs = evs + [res.evidence]
            hybrid, codes, confidence, cited = suggest_verdict(packet["row"], hybrid_evs)
            if hybrid.value != "needs_review" and not check_suggestion(finding.finding_id, hybrid, codes, cited, confidence):
                raise ValueError("hybrid verdict failed invariants")
            row.update({"llm_only": llm, "hybrid": hybrid.value, "raw_claims": raw["claims"],
                        "accepted_claims": res.accepted, "dropped_claims": res.rejected, "model": meta,
                        "hybrid_evidence": res.evidence.model_dump(mode="json")})
            human.append({"case_id": packet["case_id"], "packet_sha256": packet["packet_sha256"],
                          "response_sha256": meta["response_sha256"], "reasoning_support": "pending",
                          "assumptions": "pending", "uncertainty": "pending", "stated_risk": "pending",
                          "dropped_claims": [{"index": i, "drop_correctness": "pending", "rationale": ""}
                                             for i, _ in enumerate(res.rejected)]})
        except (ValueError, KeyError, TypeError, RuntimeError) as exc:
            row.update({"llm_only": None, "hybrid": None, "processing_failure": str(exc)})
            write_json(call_dir / "processing-failure.json", row)
            results.append(row)
            # Model identity/isolation failure must never allow the remaining batch to proceed.
            break
        results.append(row)
    (out / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in results), encoding="utf-8")
    write_json(out / "human-review.json", human)
    if smoke and len(results) == 1 and not results[0]["processing_failure"]:
        write_json(out / "smoke.json", {"prepared_sha256": manifest["sha256"], "observed_model": FIXED_MODEL})
    seal(out, "outputs.json", [p for p in out.rglob("*") if p.is_file()])
    return {"cases_processed": len(results), "cases_total": len(cases),
            "processing_failures": sum(bool(r["processing_failure"]) for r in results), "out": str(out.resolve())}


def score_cases(prepared: Path, run: Path, gold: Path, *, review: Path | None = None):
    from fva.export.score import load_key
    verify_seal(prepared, "prepared.json")
    verify_seal(run, "outputs.json")
    run_meta = json.loads((run / "run.json").read_text(encoding="utf-8"))
    expected_hash = (run_meta.get("labels_receipt") or {}).get("gold_sha256")
    if expected_hash and hashlib.sha256(gold.read_bytes()).hexdigest() != expected_hash:
        raise ValueError("gold changed after label freeze")
    if run_meta["prepared_sha256"] != verify_seal(prepared, "prepared.json")["sha256"]:
        raise ValueError("run/prepared mismatch")
    key = load_key(gold)
    rows = read_rows(run / "results.jsonl")
    all_cases = read_rows(prepared / "cases.jsonl")
    humans = {r["case_id"]: r for r in json.loads(review.read_text(encoding="utf-8"))} if review else {}
    positive, cleared = {"confirmed", "likely"}, {"not_applicable", "valid_non_security"}
    summary = {"prepared_cases": len(all_cases), "responses": len(rows),
               "unprocessed_cases": len(all_cases) - len(rows),
               "processing_failures": sum(bool(r["processing_failure"]) for r in rows),
               "llm_only_limit": "LLM-only cannot produce confirmed",
               "gold_rows": len(key), "arms": {}, "human_metrics": {},
               "coverage": json.loads((prepared / "coverage.json").read_text(encoding="utf-8"))}
    for arm in ("rules_only", "llm_only", "hybrid"):
        counts = Counter()
        n = 0
        for row in rows:
            expected = key.get(row["case_id"])
            got = row.get(arm)
            if not expected or got is None:
                continue
            n += 1
            exp = expected["verdict"]
            exact = exp == got
            relaxed = exact or exp in positive and got in positive
            counts["exact_agreement"] += exact
            counts["relaxed_agreement"] += relaxed
            counts["disagreement"] += not relaxed
            counts["false_positive_decisions"] += got in positive and exp in cleared
            counts["incorrect_clearances"] += got in cleared and exp in positive
            counts["appropriate_abstention"] += got == "needs_review" and exp == "needs_review"
            counts["unnecessary_abstention"] += got == "needs_review" and exp != "needs_review"
            counts["dast_backed_cases"] += bool(row["approved_link_ids"])
            counts["dast_backed_confirmed"] += bool(row["approved_link_ids"]) and got == "confirmed"
        summary["arms"][arm] = {"denominator": n, **dict(counts)}
    disagreements = sum(len({r[a] for a in ("rules_only", "llm_only", "hybrid") if r.get(a)}) > 1 for r in rows)
    complete = [r for r in rows if not r["processing_failure"]]
    summary["arm_disagreements"] = {"count": disagreements, "denominator": len(complete)}
    summary["citation_failures"] = {"count": sum(
        sum(c.get("_why") == "no citation verified" for c in r.get("dropped_claims", [])) +
        sum(bool(c.get("dropped_citations")) for c in r.get("accepted_claims", [])) for r in rows),
                                     "denominator": sum(len(r.get("raw_claims", [])) for r in rows)}
    discovery_counts = Counter()
    verified_cases = 0
    for packet in all_cases:
        origins = {f["source_tool"] for f in packet["original_findings"]}
        discovery, polaris = "llm-discovery" in origins, "polaris" in origins
        if discovery and polaris:
            discovery_counts["overlap_cases"] += 1
        elif polaris:
            discovery_counts["polaris_only_cases"] += 1
        elif discovery:
            discovery_counts["llm_only_cases"] += 1
            if key.get(packet["case_id"], {}).get("verified_security") is True:
                verified_cases += 1
    summary["discovery_coverage"] = {**dict(discovery_counts), "case_denominator": len(all_cases),
                                     "verified_llm_only_additions": verified_cases,
                                     "rejected_true_discoveries": "unmeasured; adjudicate rejected.json separately",
                                     "verified_plants_missed_by_both": "unmeasured; requires private coverage reconciliation"}
    graded, unsupported, drops = 0, 0, Counter()
    for row in rows:
        grade = humans.get(row["case_id"])
        if not grade:
            continue
        if grade.get("response_sha256") != row.get("model", {}).get("response_sha256") \
                or grade.get("packet_sha256") != row["packet_sha256"]:
            raise ValueError("human review response/packet mismatch")
        support = grade.get("reasoning_support")
        if support in {"supported", "unsupported", "uncertain"}:
            graded += 1
            unsupported += support == "unsupported"
        for drop in grade.get("dropped_claims", []):
            if not isinstance(drop.get("index"), int) or not 0 <= drop["index"] < len(row.get("dropped_claims", [])):
                raise ValueError("human drop review names an absent claim")
            if drop.get("drop_correctness") in {"correct", "incorrect", "uncertain"}:
                drops[drop["drop_correctness"]] += 1
    summary["human_metrics"] = {"unsupported_reasoning": {"count": unsupported, "denominator": graded}
                                if graded else "unmeasured", "drop_correctness": dict(drops) if drops else "unmeasured"}
    write_json(run / "score.json", summary)
    lines = ["# Paired evaluation score", "", "Headline agreement treats confirmed and likely as equivalent.",
             "LLM-only cannot produce confirmed. Counts and denominators only.", "",
             "| Arm | Relaxed agreement | Exact agreement | Disagreements |", "|---|---|---|---|"]
    for arm, metrics in summary["arms"].items():
        n = metrics["denominator"]
        lines.append(f"| {arm} | {metrics.get('relaxed_agreement', 0)}/{n} | "
                     f"{metrics.get('exact_agreement', 0)}/{n} | {metrics.get('disagreement', 0)}/{n} |")
    lines += ["", f"Processing failures: {summary['processing_failures']}/{len(rows)} responses.",
              f"Unprocessed cases: {summary['unprocessed_cases']}/{len(all_cases)} prepared cases.",
              "Detailed counts, DAST link references and unmeasured human categories are in score.json.",
              "Discovery coverage requires separate human adjudication, including rejected candidates and missed plants."]
    (run / "score.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def artifact_dir(path):
    out = Path(path).resolve()
    data = Path(__file__).resolve().parent.parent / "data"
    if not out.is_relative_to(data):
        raise ValueError("evaluation artifacts must stay under this repository's ignored data/ directory")
    return out


def profile_args(parser):
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--profile", choices=sorted(PROFILES))
    profiles.add_argument("--profile-file")
    parser.add_argument("--source", required=True)


def preflight(source: Path, profile, out: Path, *, expected_routes: Path | None = None,
              lockfile: Path | None = None) -> dict:
    source = source.resolve()
    if not source.is_dir():
        raise ValueError(f"source directory not found: {source}")
    unknown = set(profile.language_packs) - REGISTRY.keys()
    if unknown:
        raise ValueError(f"unknown language packs: {sorted(unknown)}")
    files = [rel for rel, _ in iter_files(source)]
    snapshot = pin(source, declared_upstream_commit=profile.source_commit)
    graph = reachability.build_graph(source, files, profile)
    routes = runtime_link.build_route_map(source, files, profile.entrypoints)
    errors = [f"missing entrypoint: {ep}" for ep in profile.entrypoints if ep not in files]
    if not profile.entrypoints:
        errors.append("profile has no entrypoints")
    rows = []
    for rel in files:
        surface, rule = match_rule(rel, profile)
        rows.append({"path": rel, "surface": surface.value, "matched_rule": rule,
                     "deployed": is_deployed(surface, profile), "reachable": rel in graph.reachable,
                     "import_path": graph.path_to(rel) if rel in graph.reachable else [],
                     "imports": sorted(graph.edges.get(rel, ()))})
    declared, installed, inventory_errors = [], [], []
    for name in profile.language_packs:
        pack = REGISTRY[name]
        for rel in files:
            if Path(rel).name == "package.json" and name == "node":
                declared.extend({"manifest": rel, **asdict(d)} for d in pack.parse_manifest(source / rel))
        inventory = lockfile or (source / "package-lock.json")
        if inventory.exists():
            try:
                installed.extend(asdict(p) for p in pack.read_inventory(inventory))
            except (ValueError, NotImplementedError) as exc:
                inventory_errors.append(str(exc))
        else:
            inventory_errors.append("no resolved inventory supplied")
    route_rows = [{"method": method, "path": path, "handlers": sorted(handlers)}
                  for (method, path), handlers in sorted(routes.items())]
    expected = None
    if expected_routes:
        expected = json.loads(expected_routes.read_text(encoding="utf-8"))
        if not isinstance(expected, list):
            raise ValueError("expected routes must be a JSON list of method/path/handlers objects")
        for row in expected:
            key = (row["method"].upper(), row["path"])
            actual = routes.get(key, set())
            if not actual or actual != set(row["handlers"]):
                errors.append(f"incorrect route mapping: {key[0]} {key[1]}")
        extras = set(routes) - {(r["method"].upper(), r["path"]) for r in expected}
        errors.extend(f"unexpected route: {m} {p}" for m, p in sorted(extras))
    else:
        errors.append("expected route list not supplied; DAST launch blocked")
    if pin(source).content_sha256 != snapshot.content_sha256:
        raise ValueError("source changed during preflight; retry with a stable checkout")
    report = {"snapshot": snapshot.model_dump(mode="json"), "profile": profile.model_dump(mode="json"),
              "profile_sha256": digest(profile.model_dump(mode="json")), "files": rows,
              "dependencies": {"declared": declared, "installed": installed, "warnings": inventory_errors},
              "routes": route_rows, "expected_routes": expected,
              "dast_ready": not errors, "blocking_reasons": errors}
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "preflight.json", report)
    lines = ["# Evaluation preflight", "", f"Source hash: {snapshot.content_sha256}",
             f"DAST launch: {'ready' if not errors else 'blocked'}", ""]
    lines += [f"- {e}" for e in errors]
    lines += ["", "| File | Boundary | Rule | Reachable |", "|---|---|---|---|"]
    lines += [f"| {r['path']} | {r['surface']} | {r['matched_rule'] or '-'} | {r['reachable']} |" for r in rows]
    lines += ["", "## Routes", ""] + [f"- {r['method']} {r['path']}: {', '.join(r['handlers'])}" for r in route_rows]
    lines += ["", "Dependency inventory and import paths are in preflight.json."]
    (out / "preflight.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fva eval")
    subs = parser.add_subparsers(dest="operation", required=True)
    prep = subs.add_parser("prepare", help="inspect source/profile without findings")
    profile_args(prep)
    prep.add_argument("--out", required=True)
    prep.add_argument("--expected-routes")
    prep.add_argument("--lockfile")
    prep.add_argument("--findings", action="append", default=[], help="Polaris export spec, repeatable")
    prep.add_argument("--canonical", action="append", default=[], help="canonical Finding JSONL, repeatable")
    prep.add_argument("--approved-links", help="human decisions with source/profile/export hashes")
    run = subs.add_parser("run", help="one fresh fixed-model response per frozen case")
    run.add_argument("prepared")
    run.add_argument("--out", required=True)
    run.add_argument("--model", required=True, choices=["gpt-6.1-sol"])
    run.add_argument("--smoke", action="store_true")
    run.add_argument("--smoke-run")
    run.add_argument("--labels-receipt", help="reviewer, prepared_sha256 and gold_sha256 only; no gold path or labels")
    score = subs.add_parser("score", help="score frozen outputs; only this operation reads gold")
    score.add_argument("prepared")
    score.add_argument("run")
    score.add_argument("--gold", required=True)
    score.add_argument("--human-review")
    args = parser.parse_args(argv)
    try:
        if args.operation == "score":
            print(score_cases(artifact_dir(args.prepared), artifact_dir(args.run), Path(args.gold),
                              review=Path(args.human_review) if args.human_review else None))
            return
        if args.operation == "run":
            print(run_cases(artifact_dir(args.prepared), artifact_dir(args.out), smoke=args.smoke,
                            smoke_run=args.smoke_run,
                            labels_receipt=Path(args.labels_receipt) if args.labels_receipt else None))
            return
        artifact_dir(args.out)
        if (args.findings or args.canonical) and Path(args.out).exists() and any(Path(args.out).iterdir()):
            raise ValueError("evaluation output must be empty; frozen packets cannot be overwritten")
        profile = load_profile(args.profile, args.profile_file)
        report = preflight(Path(args.source), load_profile(args.profile, args.profile_file), Path(args.out),
                           expected_routes=Path(args.expected_routes) if args.expected_routes else None,
                           lockfile=Path(args.lockfile) if args.lockfile else None)
        if args.findings or args.canonical:
            print(prepare_cases(Path(args.source), profile, Path(args.out), report,
                                findings_specs=args.findings, canonical_paths=args.canonical,
                                approved=args.approved_links,
                                lockfile=Path(args.lockfile) if args.lockfile else None))
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))
    print(f"Reports: {Path(args.out).resolve() / 'preflight.json'} and {Path(args.out).resolve() / 'preflight.md'}")
    print(f"DAST launch: {'ready' if report['dast_ready'] else 'blocked'}")


if __name__ == "__main__":
    main()
