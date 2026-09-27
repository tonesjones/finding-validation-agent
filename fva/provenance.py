"""Content-addressed, append-only store for raw scanner artifacts."""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def archive_raw(path: Path, store_dir: Path) -> str:
    """Copy `path` byte-identical into store_dir/<sha256><suffix>. Returns the hash."""
    digest = sha256_file(path)
    store_dir.mkdir(parents=True, exist_ok=True)
    dest = store_dir / f"{digest}{''.join(path.suffixes)}"
    if not dest.exists():
        shutil.copyfile(path, dest)
    return digest


def raw_ref(digest: str, pointer: str) -> str:
    """Pointer is a JSON Pointer (/runs/0/results/3) or 'L<n>' for line-based files."""
    return f"raw:sha256:{digest}#{pointer}"
