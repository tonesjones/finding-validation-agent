"""End-to-end evidence collection for a batch of findings (no verdicts yet).

Stages per finding: deployment boundary -> source location -> dependency reconciliation
-> static reachability -> model assessment (one model call per cluster of findings that
share the same code location or advisory).
"""
from __future__ import annotations

import glob
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fva.adapters import polaris
from fva.correlation import dependency, locate, reachability
from fva.correlation.source_pin import iter_files, pin
from fva.langpacks import REGISTRY
from fva.reasoning import assessor
from fva.schemas import DeploymentProfile, Finding, FindingType, Surface
from fva.surface import classify_finding, is_deployed


def load_findings(spec: str) -> list[Finding]:
    paths = sorted(glob.glob(spec)) or [spec]
    if len(paths) == 1 and paths[0].endswith((".jsonl", ".csv")):
        return polaris.load(Path(paths[0]))[1]
    return polaris.load_mcp(paths)[1]


def cluster_key(f: Finding) -> tuple:
    if f.finding_type is FindingType.sca and f.package:
        return ("sca", dependency.package_name(f), f.package.version, f.package.advisory_id or f.rule_id)
    loc = f.location
    return ("sast", loc.path if loc else None, loc.start_line if loc else None, f.cwe, f.rule_id)


@dataclass
class Batch:
    clusters: "OrderedDict[tuple, list[Finding]]"
    skipped: dict[str, int]
    pre_evidence: dict[str, list]  # finding_id -> evidence records
    sites: dict[tuple, list[tuple[str, int]]]


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
    pre, sites = {}, {}
    for f in findings:
        surf = classify_finding(f, profile)
        if not is_deployed(surf, profile):
            skipped[f"surface:{surf.value}"] = skipped.get(f"surface:{surf.value}", 0) + 1
            continue
        ev = []
        if f.location:
            ev.append(locate.to_evidence(locate.locate(f, idx), source_content_sha256=snapshot_sha))
        if f.package and inventory is not None:
            d = dependency.reconcile(f, inventory)
            ev.append(dependency.to_evidence(d, inventory_ref=str(lockfile.name), profile_id=profile.profile_id))
            if d.status in ("version_drift", "not_installed"):
                skipped[f"dependency:{d.status}"] = skipped.get(f"dependency:{d.status}", 0) + 1
                continue
        r = reachability.assess(f, graph, profile, declared_direct=direct)
        ev.append(reachability.to_evidence(r, source_content_sha256=snapshot_sha, profile_id=profile.profile_id))
        if r.status == "imported_only_outside_deployment":
            skipped["reachability:outside_deployment"] = skipped.get("reachability:outside_deployment", 0) + 1
            continue
        pre[f.finding_id] = ev
        key = cluster_key(f)
        clusters.setdefault(key, []).append(f)
        sites[key] = [(s.rsplit(":", 1)[0], int(s.rsplit(":", 1)[1])) for s in r.sites]
    return Batch(clusters, skipped, pre, sites)


def run(*, findings_spec: str, source_root: Path, profile: DeploymentProfile, client, out_dir: Path,
        lockfile: Path | None = None, cache_dir: Path | None = None, limit: int | None = None,
        dry_run: bool = False, log=print) -> dict:
    t0 = time.time()
    snap = pin(source_root)
    files = [r for r, _ in iter_files(source_root)]
    idx = locate.SourceIndex(source_root, files)
    graph = reachability.build_graph(source_root, files, profile)
    findings = load_findings(findings_spec)
    batch = prepare(findings, source_root, profile, lockfile, snap.content_sha256, idx, graph)
    keys = list(batch.clusters)[: limit or None]
    log(f"{len(findings)} findings -> {sum(len(batch.clusters[k]) for k in keys)} to assess in {len(keys)} clusters "
        f"(skipped: {batch.skipped})")
    out_dir.mkdir(parents=True, exist_ok=True)
    if dry_run:
        pdir = out_dir / "prompts"
        pdir.mkdir(exist_ok=True)
        for i, k in enumerate(keys, 1):
            lead = batch.clusters[k][0]
            (pdir / f"{i:04d}.txt").write_text(assessor.build_prompt(
                lead, idx, batch.pre_evidence[lead.finding_id], batch.sites.get(k, [])), encoding="utf-8")
        log(f"dry run: wrote {len(keys)} prompts to {pdir}")
        return {"clusters": len(keys), "dry_run": True}
    ev_out = open(out_dir / "evidence.jsonl", "w", encoding="utf-8")
    as_out = open(out_dir / "assessments.jsonl", "w", encoding="utf-8")
    stats = {"clusters": 0, "errors": 0, "cached": 0, "stance": {}}
    try:
        for fid, evs in batch.pre_evidence.items():
            for e in evs:
                ev_out.write(e.model_dump_json() + "\n")
        for i, k in enumerate(keys, 1):
            group = batch.clusters[k]
            lead = group[0]
            try:
                res = assessor.assess(lead, idx, client, source_content_sha256=snap.content_sha256,
                                      profile_id=profile.profile_id, evidence=batch.pre_evidence[lead.finding_id],
                                      sites=batch.sites.get(k, []), cache_dir=cache_dir,
                                      also_covers=tuple(g.finding_id for g in group[1:]))
            except Exception as e:  # keep going; record the failure
                stats["errors"] += 1
                as_out.write(json.dumps({"cluster": list(map(str, k)), "error": str(e)[:500],
                                         "source_finding_ids": [g.source_finding_id for g in group]}) + "\n")
                log(f"[{i}/{len(keys)}] ERROR {e}")
                continue
            stats["clusters"] += 1
            stats["cached"] += res.cached
            stats["stance"][res.evidence.stance.value] = stats["stance"].get(res.evidence.stance.value, 0) + 1
            ev_out.write(res.evidence.model_dump_json() + "\n")
            as_out.write(json.dumps({"cluster": list(map(str, k)),
                                     "source_finding_ids": [g.source_finding_id for g in group],
                                     "finding_ids": [g.finding_id for g in group],
                                     "stance": res.evidence.stance.value, "accepted": res.accepted,
                                     "rejected": res.rejected, "cached": res.cached}) + "\n")
            as_out.flush()
            log(f"[{i}/{len(keys)}] {res.evidence.stance.value:12s} {lead.title[:60]}"
                f"{' (cached)' if res.cached else ''}")
    finally:
        ev_out.close()
        as_out.close()
    summary = {"run_at": datetime.now(timezone.utc).isoformat(), "model": client.model_id,
               "prompt_version": assessor.PROMPT_VERSION, "profile": profile.profile_id,
               "source_content_sha256": snap.content_sha256, "findings_total": len(findings),
               "skipped": batch.skipped, **stats, "seconds": round(time.time() - t0, 1)}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary
