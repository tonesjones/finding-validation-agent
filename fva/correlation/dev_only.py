"""Conservative dev-only closure from a full-tree text scan and npm lockfile."""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fva.correlation.dependency import DependencyResult
from fva.langpacks.base import InstalledPackage
from fva.schemas import DeploymentProfile, EvidenceRecord, EvidenceType, Stance, Surface
from fva.surface import classify_path

_NS = uuid.UUID("c40f893a-25e2-41bd-b937-673939796a94")
_SKIP = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
_SURFACES = {Surface.test, Surface.fixture, Surface.documentation, Surface.api_spec}


@dataclass
class DevOnlyIndex:
    dev_names: set[str]
    referenced: set[str]
    closure: set[str]
    scanned_files: int
    complete: bool

    def evidence(self, result: DependencyResult, profile_id: str) -> EvidenceRecord | None:
        name = result.package
        if (not self.complete or result.status != "scanned_version_present" or name not in self.dev_names
                or name in self.referenced or name in self.closure):
            return None
        return EvidenceRecord(
            evidence_id=str(uuid.uuid5(_NS, f"{result.finding_id}:{profile_id}:{name}")),
            finding_ids=(result.finding_id,), evidence_type=EvidenceType.dependency_resolution,
            method="dev_only:not_shipped", stance=Stance.refutes, deployment_profile_id=profile_id,
            summary=f"{name}: scanned version present; every installed instance is dev; "
                    f"no reference in {self.scanned_files} counted text files; absent from lockfile closure "
                    f"of {len(self.referenced)} referenced package names",
            collected_at=datetime.now(timezone.utc))


def build_index(root: Path, lockfile: Path | None, inventory: list[InstalledPackage] | None,
                profile: DeploymentProfile) -> DevOnlyIndex:
    index = DevOnlyIndex(set(), set(), set(), 0, False)
    if lockfile is None or inventory is None:
        return index
    by_name = {}
    for p in inventory:
        by_name.setdefault(p.name, []).append(p)
    index.dev_names = {name for name, instances in by_name.items() if all(p.dev for p in instances)}
    try:
        packages = json.loads(lockfile.read_text(encoding="utf-8"))["packages"]
        if not isinstance(packages, dict):
            return index
        edges = {}
        for path, meta in packages.items():
            if not isinstance(meta, dict):
                return index
            if "node_modules/" not in path:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            deps = edges.setdefault(name, set())
            for key in ("dependencies", "optionalDependencies", "peerDependencies"):
                values = meta.get(key, {})
                if not isinstance(values, dict):
                    return index
                deps.update(values)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return index
    if not by_name:
        return index
    # Bare bounded mentions also block: comments and shell/config uses are safer to overcount.
    pattern = re.compile(r"(?<![\w@.-])(?:" + "|".join(re.escape(n) for n in sorted(by_name, key=len, reverse=True))
                         + r")(?![\w@.-])")
    index.complete = True

    def failed(_):
        index.complete = False

    for directory, dirs, files in os.walk(root, onerror=failed):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git"}]
        for filename in files:
            path = Path(directory) / filename
            rel = path.relative_to(root).as_posix()
            if filename in _SKIP or classify_path(rel, profile) in _SURFACES:
                continue
            try:
                if path.is_symlink():
                    index.complete = False  # A linked file may point outside the scanned tree.
                    continue
                raw = path.read_bytes()
            except OSError:
                index.complete = False
                continue
            if b"\0" in raw:
                continue
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeError:
                continue
            index.scanned_files += 1
            index.referenced.update(m.group() for m in pattern.finditer(text))
        if any((Path(directory) / d).is_symlink() for d in dirs):
            index.complete = False
    # Walk from every referenced name, not only dev ones: a dev-flagged peer of a shipped package still ships.
    pending = list(index.referenced)
    while pending:
        name = pending.pop()
        if name in index.closure:
            continue
        index.closure.add(name)
        pending.extend(edges.get(name, set()) - index.closure)
    return index
