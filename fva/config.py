"""Model settings written by `python -m fva setup` and read by `assess`.

The file names the client, the gateway URL, the environment variable that holds the key, and a model per tier.
It never holds the key itself. It lives under `data/` by default, which is never committed, because a company
gateway URL is internal.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_PATH = Path("data/fva-config.json")
DEFAULT_KEY_ENV = "FVA_GATEWAY_KEY"


def path() -> Path:
    return Path(os.environ.get("FVA_CONFIG", DEFAULT_PATH))


def load() -> dict | None:
    p = path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def save(cfg: dict) -> Path:
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=1) + "\n", encoding="utf-8")
    return p
