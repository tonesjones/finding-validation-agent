"""Node.js / npm language pack."""
from __future__ import annotations

import json
from pathlib import Path

from fva.langpacks.base import DeclaredDependency, InstalledPackage
from fva.schemas import Surface as S


class NodePack:
    name = "node"
    ecosystem = "npm"
    path_rules = (
        ("**/node_modules/*", S.dependency),
        ("test/*", S.test),
        ("tests/*", S.test),
        ("**/__tests__/*", S.test),
        ("**/cypress/*", S.test),
        ("**/e2e/*", S.test),
        ("**/*.spec.ts", S.test),
        ("**/*.spec.js", S.test),
        ("**/*.test.ts", S.test),
        ("**/*.test.js", S.test),
        ("**/*.spec.tsx", S.test),
        ("**/*.test.tsx", S.test),
    )
    manifest_files = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

    def parse_manifest(self, path: Path) -> list[DeclaredDependency]:
        if path.name != "package.json":
            raise NotImplementedError(f"{path.name} parsing not built yet")
        data = json.loads(path.read_text(encoding="utf-8"))
        out = []
        for key, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                           ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
            for name, spec in (data.get(key) or {}).items():
                out.append(DeclaredDependency(name, spec, "npm", scope))
        return out

    def read_inventory(self, path: Path) -> list[InstalledPackage]:
        """package-lock.json / npm-shrinkwrap.json (lockfileVersion 2/3), or a node_modules directory."""
        path = Path(path)
        if path.is_dir():
            return self._walk_node_modules(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        pkgs = data.get("packages")
        if pkgs is None:
            raise NotImplementedError("lockfileVersion 1 not supported; regenerate with npm >= 7")
        out = []
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or "version" not in meta or meta.get("link"):
                continue
            out.append(InstalledPackage(meta.get("name") or key.rsplit("node_modules/", 1)[-1], meta["version"],
                                        "npm", key, bool(meta.get("dev"))))
        return out

    def _walk_node_modules(self, nm: Path) -> list[InstalledPackage]:
        out = []
        for pj in nm.rglob("package.json"):
            rel = pj.parent.relative_to(nm.parent).as_posix()
            if not rel.rsplit("node_modules/", 1)[-1] or rel.count("/") > rel.count("node_modules/") + rel.count("@"):
                continue  # skip nested non-package dirs (tests, fixtures inside packages)
            try:
                meta = json.loads(pj.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if meta.get("name") and meta.get("version"):
                out.append(InstalledPackage(meta["name"], meta["version"], "npm", rel))
        return out
