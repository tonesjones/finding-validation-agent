"""Pin the exact source a set of findings is correlated against.

Handles both a real clone and an archive import (e.g. a release tarball committed
locally as "Initial import"), where the local commit differs from the upstream
commit the scanner saw. The content hash is line-ending-normalized so a Windows
CRLF checkout and a Linux LF checkout of the same source pin identically.
"""
from __future__ import annotations

import hashlib
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
        r = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def iter_files(root: Path, excludes=DEFAULT_EXCLUDES):
    """Tracked files when `root` is a git repo (ignores untracked outputs dropped into it), else a walk."""
    tracked = _git(root, "ls-files", "-z")
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
        dirty = bool(_git(root, "diff", "--ignore-cr-at-eol", "--stat", "HEAD"))
    return SourceSnapshot(root_name=root.name, vcs_commit=head, vcs_dirty=dirty,
                          declared_upstream_commit=declared_upstream_commit, content_sha256=h.hexdigest(),
                          file_count=n, excluded_dirs=tuple(excludes), pinned_at=datetime.now(timezone.utc))
