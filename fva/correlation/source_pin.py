"""Pin the exact source a set of findings is correlated against.

Handles both a real clone and an archive import (e.g. a release tarball committed
locally as "Initial import"), where the local commit differs from the upstream
commit the scanner saw. The content hash is line-ending-normalized so a Windows
CRLF checkout and a Linux LF checkout of the same source pin identically.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

DEFAULT_EXCLUDES = ("node_modules", ".git", "dist", "build", "__pycache__", ".venv", "vendor", "target")
TEXT_LIMIT = 5 * 1024 * 1024


class SourceSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    root_name: str
    vcs_commit: str | None  # local HEAD, if a git repo
    vcs_dirty: bool | None  # tracked content changes vs HEAD, ignoring line endings
    declared_upstream_commit: str | None  # what the scan/profile says it should be
    content_sha256: str  # normalized tree hash over included files
    file_count: int
    excluded_dirs: tuple[str, ...]
    pinned_at: datetime


def _git(root: Path, *args: str) -> str | None:
    try:
        # --no-optional-locks: never write .git/index (we must not leave lock files in user repos)
        command = ["git", "-c", f"safe.directory={root.resolve().as_posix()}",
                   "-c", "core.fsmonitor=", "-c", f"core.hooksPath={os.devnull}",
                   "--no-optional-locks", "-C", str(root)]
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(root.resolve().parent)}
        if args and args[0] == "diff":
            # Worktree diffs can run clean/process filters even without textconv.
            config = subprocess.run(command + ["config", "--includes", "--null", "--name-only",
                                    "--get-regexp", r"^filter\..*\.(clean|process|required)$"],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    timeout=120, env=env)
            if config.returncode not in (0, 1):
                return None
            drivers = {key.rsplit(".", 1)[0] for key in config.stdout.split("\0") if key}
            for driver in sorted(drivers):
                if "=" in driver:
                    return None
                command += ["-c", f"{driver}.clean=", "-c", f"{driver}.process=",
                            "-c", f"{driver}.required=false"]
            args = ("diff", "--no-ext-diff", "--no-textconv", *args[1:])
        r = subprocess.run([*command, *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                           env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (r.stdout or "").strip() if r.returncode == 0 else None


def iter_files(root: Path, excludes=DEFAULT_EXCLUDES):
    """Tracked files when `root` is a git repo (ignores untracked outputs dropped into it), else a walk."""
    tracked = _git(root, "ls-files", "-z")
    if tracked is None and (root / ".git").exists():
        raise ValueError("cannot read Git tracked-file inventory; refusing archive fallback. "
                         "Check that Git is installed and the repository is readable.")
    if tracked is not None:
        for rel in sorted(t for t in tracked.split("\0") if t):
            if not any(part in excludes for part in rel.split("/")) and (root / rel).is_file():
                yield rel, root / rel
        return
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in excludes for part in rel.parts[:-1]) or rel.parts[0] in excludes:
            continue
        if p.is_file():
            yield rel.as_posix(), p


def normalized_bytes(p: Path) -> bytes:
    b = p.read_bytes()
    if len(b) <= TEXT_LIMIT and b"\0" not in b[:8192]:
        b = b.replace(b"\r\n", b"\n")
    return b


def pin(root: Path, *, declared_upstream_commit: str | None = None,
        excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> SourceSnapshot:
    root = Path(root)
    h = hashlib.sha256()
    n = 0
    for rel, p in iter_files(root, excludes):
        h.update(rel.encode() + b"\0" + hashlib.sha256(normalized_bytes(p)).digest())
        n += 1
    head = _git(root, "rev-parse", "HEAD")
    dirty = None
    if head is not None:
        changes = _git(root, "diff", "--ignore-cr-at-eol", "--stat", "HEAD")
        dirty = bool(changes) if changes is not None else None
    return SourceSnapshot(root_name=root.name, vcs_commit=head, vcs_dirty=dirty,
                          declared_upstream_commit=declared_upstream_commit, content_sha256=h.hexdigest(),
                          file_count=n, excluded_dirs=tuple(excludes), pinned_at=datetime.now(timezone.utc))
