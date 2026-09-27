"""Language-pack interface.

Everything language- or ecosystem-specific lives behind this interface so the rest
of the pipeline (schemas, adapters, verdicts, runtime probes) stays language-neutral.
A pack answers three questions:

1. classify_path   - is this path test / fixture / production code by ecosystem convention?
2. manifest_files  - which files declare dependencies (for SCA reconciliation)?
3. parse_manifest  - what does a manifest declare?
4. read_inventory  - what is actually resolved/installed (lockfile or installed tree)?

App-specific quirks (e.g. Juice Shop's data/static/codefixes) do NOT go in a pack;
they go in DeploymentProfile.extra_path_rules.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fva.schemas import Surface


@dataclass(frozen=True)
class DeclaredDependency:
    name: str
    spec: str  # version or range as written
    ecosystem: str
    scope: str  # "runtime" | "dev" | "optional" | "peer"


def glob_match(path: str, pattern: str) -> bool:
    """fnmatch with '**/' allowed to match zero directories."""
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
        return True
    return False


@dataclass(frozen=True)
class InstalledPackage:
    name: str
    version: str
    ecosystem: str
    install_path: str  # e.g. node_modules/a/node_modules/b
    dev: bool = False


class LanguagePack(Protocol):
    name: str
    ecosystem: str
    path_rules: tuple[tuple[str, Surface], ...]  # ordered; first match wins
    manifest_files: tuple[str, ...]

    def parse_manifest(self, path: Path) -> list[DeclaredDependency]: ...

    def read_inventory(self, path: Path) -> list[InstalledPackage]:
        """Installed/resolved packages from a lockfile or an installed tree (e.g. node_modules)."""
        ...
