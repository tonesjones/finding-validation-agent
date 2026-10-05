"""End-to-end evidence collection for a batch of findings (no verdicts yet).

Stages per finding: deployment boundary -> source location -> dependency reconciliation
-> static reachability -> model assessment (one model call per cluster of findings that
share the same code location or advisory).

Any scanner mix works: SAST+SCA only (non-web apps, no DAST) skips DAST linking and runtime
evidence; DAST findings, when present, are linked to SAST sinks and grouped, never sent to the model.

`run(workers=N)` makes the per-cluster model calls in N threads (default 1 = sequential); results are still
consumed in cluster order on the main thread, so output files and log lines are unchanged apart from timings.
"""
from __future__ import annotations

import glob
import json
import time
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fva.adapters import polaris
from fva import runtime_mode, surface
from fva.correlation import (advisory_applicability, dast_evidence, dependency, grouping, locate, package_link, quality,
                             reachability, runtime_link)
from fva.correlation.source_pin import iter_files, pin
from fva.langpacks import REGISTRY
from fva.reasoning import assessor, pricing
from fva.reasoning.routing import Router
from fva.redact import CREDENTIAL_CWES
from fva.schemas import DeploymentProfile, Finding, FindingType, RuntimeMode, Surface
from fva.surface import classify_finding, is_deployed


def load_findings(spec: str) -> list[Finding]:
    paths = sorted(glob.glob(spec)) or [spec]
    if len(paths) == 1 and paths[0].endswith((".jsonl", ".csv")):
        return polaris.load(Path(paths[0]))[1]
    return polaris.load_mcp(paths)[1]


def scanner_mix(findings: list[Finding]) -> list[str]:
    """Scanner types present in this run, e.g. ["sast", "sca"] for a non-web app without DAST."""
    return sorted({f.finding_type.value for f in findings})


def cluster_key(f: Finding) -> tuple:
    if f.finding_type is FindingType.sca and f.package:
        return ("sca", dependency.package_name(f), f.package.version, f.package.advisory_id or f.rule_id)
    loc = f.location
    return ("sast", loc.path if loc else None, loc.start_line if loc else None, f.cwe, f.rule_id)


@dataclass
class Batch:
    clusters: "OrderedDict[tuple, list[Finding]]"
    skipped: dict[str, int]
    pre_evidence: dict[str, list]  # finding_id -> evidence records (assessed and rule-skipped findings)
    sites: dict[tuple, list[tuple[str, int]]]
    disposition: dict[str, str]  # finding_id -> "assess" or the skip reason (e.g. "surface:test")


def prepare(findings: list[Finding], source_root: Path, profile: DeploymentProfile, lockfile: Path | None,
            snapshot_sha: str, idx: locate.SourceIndex, graph: reachability.CodeGraph) -> Batch:
    inventory = None
    if lockfile:
        pack = REGISTRY[profile.language_packs[0]]
        inventory = pack.read_inventory(lockfile)
    direct = set()
    for name in profile.language_packs:
        mf = source_root / "package.json"
        if name == "node" and mf.exists():
            direct = {d.name for d in REGISTRY["node"].parse_manifest(mf) if d.scope == "runtime"}
    clusters: OrderedDict = OrderedDict()
    skipped: dict[str, int] = {}
    pre, sites, disp = {}, {}, {}
    calls: dict = {}

    def skip(f: Finding, why: str, ev: list):
        """Rule-decided finding: keep the evidence the rule used, so the closure can cite it."""
        skipped[why] = skipped.get(why, 0) + 1
        disp[f.finding_id] = why
        pre[f.finding_id] = ev

    for f in findings:
        surf = classify_finding(f, profile)
        if not is_deployed(surf, profile):
            skip(f, f"surface:{surf.value}", [surface.to_evidence(f, profile)])
            continue
        ev, called = [], []
        if f.location:
            ev.append(locate.to_evidence(locate.locate(f, idx), source_content_sha256=snapshot_sha))
        if name := quality.checker(f):
            ev.append(quality.to_evidence(f, name, profile.profile_id))
            skip(f, f"quality:{name}", ev)
            continue
        if f.package and inventory is not None:
            d = dependency.reconcile(f, inventory)
            ev.append(dependency.to_evidence(d, inventory_ref=str(lockfile.name), profile_id=profile.profile_id))
            if d.status in ("version_drift", "not_installed"):
                skip(f, f"dependency:{d.status}", ev)
                continue
            if d.status == "scanned_version_present" and len(d.installed_versions) == 1:
                applies = advisory_applicability.applicable(f, d.installed_versions[0])
                if applies is not None:
                    ev.append(advisory_applicability.to_evidence(
                        f, d.installed_versions[0], applies, profile.profile_id))
                    if not applies:
                        skip(f, "dependency:advisory_version_unaffected", ev)
                        continue
                    name = f.package.name.lower()
                    if name not in calls:  # one source scan and lockfile read per package per run
                        calls[name] = (advisory_applicability.scan(source_root, sorted(graph.files), profile, name),
                                       REGISTRY["node"].dependents(lockfile, f.package.name))
                    use = advisory_applicability.use_evidence(f, *calls[name], profile.profile_id)
                    if use:
                        ev.append(use[0])
                        if use[1]:
                            skip(f, use[1], ev)
                            continue
                        called = advisory_applicability.called_at(f, calls[name][0])
        r = reachability.assess(f, graph, profile, declared_direct=direct)
        ev.append(reachability.to_evidence(r, source_content_sha256=snapshot_sha, profile_id=profile.profile_id))
        if r.status == "imported_only_outside_deployment":
            skip(f, "reachability:outside_deployment", ev)
            continue
        disp[f.finding_id] = "assess"
        pre[f.finding_id] = ev
        key = cluster_key(f)
        clusters.setdefault(key, []).append(f)
        sites[key] = called + [(s.rsplit(":", 1)[0], int(s.rsplit(":", 1)[1])) for s in r.sites]
    return Batch(clusters, skipped, pre, sites, disp)


def link_and_group(findings: list[Finding], source_root: Path, files: list[str], profile: DeploymentProfile,
                   idx: locate.SourceIndex, graph: reachability.CodeGraph, mode: RuntimeMode):
    """SCA<->SAST links always; SAST<->DAST links and DAST evidence only when the scan has DAST."""
    by = {t: [f for f in findings if f.finding_type is t] for t in FindingType}
    links = package_link.link_all(by[FindingType.sca], by[FindingType.sast], graph, profile)
    dast_ev = []
    if by[FindingType.dast]:
        routes = runtime_link.build_route_map(source_root, files, profile.entrypoints)
        source = {f.location.path: idx.lines(f.location.path) for f in by[FindingType.sast]
                  if f.location and f.location.path in idx.files}
        dlinks = runtime_link.link_all(by[FindingType.sast], by[FindingType.dast], routes, source)
        links += dlinks
        dast_ev = [e for l in dlinks if (e := dast_evidence.to_evidence(l, profile_id=profile.profile_id, mode=mode))]
    return links, grouping.group(findings, links), dast_ev


def write_findings_index(out_dir: Path, findings: list[Finding], batch: Batch, issues) -> None:
    """One row per original scanner finding: what happened to it and which grouped issue holds it."""
    issue_of = {fid: g.issue_id for g in issues for fid in g.finding_ids}
    primary = {g.primary_finding_id for g in issues}
    with open(out_dir / "findings.jsonl", "w", encoding="utf-8") as fh:
        for f in findings:
            loc = f.location
            fh.write(json.dumps({
                "finding_id": f.finding_id, "source_finding_id": f.source_finding_id, "source_tool": f.source_tool,
                "finding_type": f.finding_type.value, "title": f.title, "severity": f.severity.value,
                "cwe": list(f.cwe), "path": loc.path if loc else None, "line": loc.start_line if loc else None,
                "package": f"{f.package.name}@{f.package.version}" if f.package else None,
                "endpoint": f"{f.endpoint.method} {f.endpoint.path}" if getattr(f, "endpoint", None) else None,
                "disposition": batch.disposition.get(f.finding_id, "runtime_only" if f.finding_type is FindingType.dast
                                                     else "assess"),
                "issue_id": issue_of.get(f.finding_id), "primary": f.finding_id in primary,
                "triage_status": f.scanner_metadata.get("triage_status")}) + "\n")


def run(*, findings_spec: str, source_root: Path, profile: DeploymentProfile, client, out_dir: Path,
        lockfile: Path | None = None, cache_dir: Path | None = None, limit: int | None = None,
        dry_run: bool = False, workers: int = 1, credential_model: str = "ask", prices: dict | None = None,
        log=print) -> dict:
    """`credential_model="skip"`: clusters made only of hard-coded-credential findings get no model call; only a
    runtime test can tell whether a credential is active, and their rule evidence is still recorded."""
    t0 = time.time()
    router = client if isinstance(client, Router) else Router.single(client)
    snap = pin(source_root)
    files = [r for r, _ in iter_files(source_root)]
    idx = locate.SourceIndex(source_root, files)
    graph = reachability.build_graph(source_root, files, profile)
    findings = load_findings(findings_spec)
    mix = scanner_mix(findings)
    mode = runtime_mode.default_for(mix)
    batch = prepare([f for f in findings if f.finding_type is not FindingType.dast], source_root, profile,
                    lockfile, snap.content_sha256, idx, graph)
    links, issues, dast_ev = link_and_group(findings, source_root, files, profile, idx, graph, mode)
    if credential_model == "skip":
        for k in [k for k, g in batch.clusters.items() if all(set(f.cwe) & CREDENTIAL_CWES for f in g)]:
            for f in batch.clusters.pop(k):
                batch.disposition[f.finding_id] = "model:credential_runtime_only"
                batch.skipped["model:credential_runtime_only"] = batch.skipped.get("model:credential_runtime_only", 0) + 1
    keys = list(batch.clusters)[: limit or None]
    log(f"{len(findings)} findings -> {sum(len(batch.clusters[k]) for k in keys)} to assess in {len(keys)} clusters "
        f"(skipped: {batch.skipped}); scanners {'+'.join(mix)}, runtime mode {mode.value}, "
        f"{len(issues)} grouped issues from {len(links)} links")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "groups.jsonl", "w", encoding="utf-8") as fh:
        for g in issues:
            fh.write(g.model_dump_json() + "\n")
    with open(out_dir / "links.jsonl", "w", encoding="utf-8") as fh:
        for l in links:
            fh.write(l.model_dump_json() + "\n")
    write_findings_index(out_dir, findings, batch, issues)
    if dry_run:
        pdir = out_dir / "prompts"
        pdir.mkdir(exist_ok=True)
        for i, k in enumerate(keys, 1):
            lead = batch.clusters[k][0]
            (pdir / f"{i:04d}.txt").write_text(assessor.build_prompt(
                lead, idx, batch.pre_evidence[lead.finding_id], batch.sites.get(k, [])), encoding="utf-8")
        tiers: dict[str, int] = {}
        with open(out_dir / "routing.jsonl", "w", encoding="utf-8") as fh:
            for i, k in enumerate(keys, 1):
                tier, why = router.plan(batch.clusters[k])
                tiers[tier] = tiers.get(tier, 0) + 1
                fh.write(json.dumps({"prompt": f"{i:04d}", "cluster": list(map(str, k)), "tier": tier,
                                     "reason": why}) + "\n")
        log(f"dry run: wrote {len(keys)} prompts to {pdir}; first-pass tiers {tiers}")
        return {"clusters": len(keys), "dry_run": True, "first_pass_tiers": tiers, "scanner_mix": mix,
                "runtime_mode": mode.value, "grouped_issues": len(issues)}
    ev_out = open(out_dir / "evidence.jsonl", "w", encoding="utf-8")
    as_out = open(out_dir / "assessments.jsonl", "w", encoding="utf-8")
    stats = {"clusters": 0, "errors": 0, "cached": 0, "stance": {}, "tiers": {}, "escalations": {}}
    cost = pricing.new_cost()
    try:
        for fid, evs in batch.pre_evidence.items():
            for e in evs:
                ev_out.write(e.model_dump_json() + "\n")
        for e in dast_ev:
            ev_out.write(e.model_dump_json() + "\n")

        def call(k):
            """Assess one cluster; return the RoutedResult, or the exception (recorded in order by the consumer)."""
            group = batch.clusters[k]
            try:
                return router.assess(group, idx, source_content_sha256=snap.content_sha256,
                                     profile_id=profile.profile_id, evidence=batch.pre_evidence[group[0].finding_id],
                                     sites=batch.sites.get(k, []), cache_dir=cache_dir,
                                     also_covers=tuple(g.finding_id for g in group[1:]))
            except Exception as e:  # keep going; record the failure
                return e

        pool = ThreadPoolExecutor(max_workers=workers) if workers > 1 else None
        try:
            if pool:  # submit everything now; results are consumed below in cluster order
                futures = [pool.submit(call, k) for k in keys]
                results = (f.result() for f in futures)
            else:  # sequential: call lazily so each cluster is assessed right before it is written
                results = (call(k) for k in keys)
            for i, (k, routed) in enumerate(zip(keys, results), 1):
                group = batch.clusters[k]
                lead = group[0]
                if isinstance(routed, Exception):
                    e = routed
                    stats["errors"] += 1
                    as_out.write(json.dumps({"cluster": list(map(str, k)), "error": str(e)[-2000:],
                                             "tier": router.plan(group)[0],
                                             "source_finding_ids": [g.source_finding_id for g in group]}) + "\n")
                    log(f"[{i}/{len(keys)}] ERROR {e}")
                    continue
                res = routed.result
                for a in routed.attempts:
                    t = stats["tiers"].setdefault(a["tier"], {"calls": 0, "cached": 0, "seconds": 0.0, "rejected": 0,
                                                               "tokens": 0, "tokens_unknown": 0, "stance": {},
                                                               "agent_models": {}})
                    pricing.add_call(t.setdefault("cost", pricing.new_cost()), a, prices)
                    pricing.add_call(cost, a, prices)
                    t["calls"] += 1
                    if a["tokens"] is None:
                        t["tokens_unknown"] += 1
                    else:
                        t["tokens"] += a["tokens"]
                    t["cached"] += a["cached"]
                    t["seconds"] = round(t["seconds"] + a["seconds"], 1)
                    t["rejected"] += a["rejected"]
                    t["stance"][a["stance"]] = t["stance"].get(a["stance"], 0) + 1
                    t["agent_models"][a["agent_model"]] = t["agent_models"].get(a["agent_model"], 0) + 1
                    if a.get("escalate"):
                        stats["escalations"][a["escalate"]] = stats["escalations"].get(a["escalate"], 0) + 1
                stats["clusters"] += 1
                stats["cached"] += res.cached
                stats["stance"][res.evidence.stance.value] = stats["stance"].get(res.evidence.stance.value, 0) + 1
                ev_out.write(res.evidence.model_dump_json() + "\n")
                as_out.write(json.dumps({"cluster": list(map(str, k)),
                                         "source_finding_ids": [g.source_finding_id for g in group],
                                         "finding_ids": [g.finding_id for g in group],
                                         "stance": res.evidence.stance.value, "accepted": res.accepted,
                                         "rejected": res.rejected, "cached": res.cached,
                                         "confidence": res.confidence, "tier": routed.tier,
                                         "routing_reason": routed.reason, "agent_model": res.agent_model,
                                         "attempts": routed.attempts}) + "\n")
                as_out.flush()
                log(f"[{i}/{len(keys)}] {routed.tier:6s} {res.evidence.stance.value:12s} {lead.title[:60]}"
                    f"{' (cached)' if res.cached else ''}")
        finally:
            if pool:
                pool.shutdown(wait=True, cancel_futures=True)
    finally:
        ev_out.close()
        as_out.close()
    summary = {"run_at": datetime.now(timezone.utc).isoformat(), "model": router.model_id,
               "prompt_version": assessor.PROMPT_VERSION, "profile": profile.profile_id,
               "source_content_sha256": snap.content_sha256, "findings_total": len(findings),
               "scanner_mix": mix, "runtime_mode": mode.value, "grouped_issues": len(issues), "links": len(links),
               "skipped": batch.skipped, **stats, "cost": pricing.finish(cost), "seconds": round(time.time() - t0, 1)}
    for t in stats["tiers"].values():
        pricing.finish(t["cost"])
    log(pricing.summary_line(summary["cost"]))
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary
