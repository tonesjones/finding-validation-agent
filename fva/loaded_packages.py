"""Loaded-package collector for Node. Passive: FVA starts nothing and sends no traffic.

The operator runs the app's own tests or a startup check with the preload in
`fva/node/loaded_modules.cjs`, which appends each module file a process loads. `receipt` maps
those files to `name@version` through each package's `package.json` and writes a
`fva.runtime_observation/1` receipt for the run's SCA findings. `import` rebuilds the receipt
from the raw records and accepts it only on an exact match.

A package counts as not loaded only when every process had load hooks (so ESM imports were
seen) and every record is intact; otherwise the receipt holds only packages that did load.
npm's nested `node_modules` layout under the source root is supported; pnpm stores are not.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fva import observations
from fva.correlation.dependency import NAME_ALIASES
from fva.correlation.source_pin import pin
from fva.runtime import digest, file_digest, read_rows

PRELOAD = Path(__file__).parent / "node" / "loaded_modules.cjs"
RAW_FORMAT = "fva.loaded_modules/1"
COLLECTOR = {"name": "fva-node-loaded-modules", "version": "1"}


def read_raw(raw: Path) -> tuple[set[str], bool, str]:
    """Loaded file paths, whether absences can be trusted, and a hash over all record files."""
    paths = sorted(raw.glob("loaded-*.jsonl"))
    if not paths:
        raise ValueError("no loaded-module records found")
    loaded, complete, hashes = set(), True, {}
    for path in paths:
        data = path.read_bytes()
        hashes[path.name] = hashlib.sha256(data).hexdigest()
        lines = data.decode("utf-8").splitlines()
        header = json.loads(lines[0]) if lines else {}
        if header.get("format") != RAW_FORMAT:
            raise ValueError(f"{path.name} is not a loaded-module record")
        complete &= header.get("hooks") is True
        for line in lines[1:]:
            try:
                loaded.add(json.loads(line))
            except json.JSONDecodeError:
                complete = False  # a process was killed mid-write; its last path is lost
    return loaded, complete, digest(hashes)


def _identity(package_dir: Path) -> tuple[str, str] | None:
    try:
        meta = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(meta.get("name"), str) and isinstance(meta.get("version"), str):
        return meta["name"], meta["version"]
    return None


def _package_dir(file: Path) -> Path | None:
    parts = file.parts
    at = max((i for i, p in enumerate(parts) if p == "node_modules"), default=None)
    if at is None or at + 1 >= len(parts):
        return None
    end = at + (3 if parts[at + 1].startswith("@") else 2)
    return Path(*parts[:end]) if end < len(parts) else None


def installed(source: Path) -> set[tuple[str, str]]:
    found, stack = set(), [source / "node_modules"]
    while stack:
        modules = stack.pop()
        if not modules.is_dir():
            continue
        for entry in modules.iterdir():
            if entry.name.startswith("."):
                continue
            for package_dir in (entry.iterdir() if entry.name.startswith("@") and entry.is_dir() else [entry]):
                if ident := _identity(package_dir):
                    found.add(ident)
                stack.append(package_dir / "node_modules")
    return found


def loaded_packages(files: set[str], source: Path) -> set[tuple[str, str]]:
    root = os.path.normcase(os.path.realpath(source))
    found, seen_dirs = set(), set()
    for name in files:
        real = os.path.realpath(name)
        if not os.path.normcase(real).startswith(root + os.sep):
            continue  # the preload itself, global installs, other checkouts
        package_dir = _package_dir(Path(real))
        if package_dir and package_dir not in seen_dirs:
            seen_dirs.add(package_dir)
            if ident := _identity(package_dir):
                found.add(ident)
    return found


def _sca_packages(run: Path) -> dict[tuple[str, str], list[str]]:
    by_package = defaultdict(list)
    for row in read_rows(run / "findings.jsonl"):
        name, _, version = (row.get("package") or "").rpartition("@")
        if row.get("finding_type") == "sca" and name and version:
            by_package[(NAME_ALIASES.get((row.get("source_tool"), name), name), version)].append(row["finding_id"])
    return by_package


def build_receipt(run: Path, raw: Path, source: Path, exercise: str, collected_at: str | None = None) -> dict:
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    if pin(source).content_sha256 != summary.get("source_content_sha256"):
        raise ValueError("source does not match the run's source_content_sha256")
    files, complete, raw_hash = read_raw(raw)
    loaded = loaded_packages(files, source)
    absent_ok = installed(source) if complete else set()
    rows = []
    for (name, version), fids in sorted(_sca_packages(run).items()):
        if (name, version) in loaded or (name, version) in absent_ok:
            rows.append({"kind": "loaded_package", "finding_ids": sorted(fids),
                         "observed": (name, version) in loaded, "subject": {"name": name, "version": version}})
    if not rows:
        raise ValueError("no SCA finding matches a loaded or installed package")
    receipt = {"format": observations.FORMAT, "profile_id": summary.get("profile"),
               "source_content_sha256": summary["source_content_sha256"],
               "findings_sha256": file_digest(run / "findings.jsonl"), "collector": COLLECTOR,
               "exercise": exercise, "raw_file": {"name": raw.name, "sha256": raw_hash},
               "collected_at": collected_at or datetime.now(timezone.utc).isoformat(), "observations": rows}
    observations.Receipt.model_validate(receipt)
    return receipt


def verify(receipt: dict, run: Path, raw: Path, source: Path) -> None:
    if receipt.get("collector") != COLLECTOR:
        raise ValueError("receipt was not written by this collector")
    rebuilt = build_receipt(run, raw, source, receipt["exercise"], receipt["collected_at"])
    if digest(rebuilt) != digest(receipt):
        raise ValueError("receipt does not match its raw loaded-module records")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fva loaded-packages")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preload", help="print the preload path and how to run with it")
    rec = commands.add_parser("receipt", help="map raw loaded-module records to a receipt")
    imp = commands.add_parser("import", help="verify a receipt against its raw records into a new run")
    for p in (rec, imp):
        p.add_argument("run", type=Path)
        p.add_argument("--raw", type=Path, required=True, help="FVA_LOADED_MODULES_DIR used for the collection")
        p.add_argument("--source", type=Path, required=True)
    rec.add_argument("--exercise", required=True, help='how the app ran, e.g. "npm test" or "startup only"')
    rec.add_argument("--out", type=Path, required=True)
    imp.add_argument("receipt", type=Path)
    imp.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "preload":
        print(f'FVA_LOADED_MODULES_DIR=<new dir under data/> NODE_OPTIONS="--require {PRELOAD}" <npm test | npm start>')
        return None
    if args.command == "receipt":
        receipt = build_receipt(args.run, args.raw, args.source, args.exercise)
        with args.out.open("x", encoding="utf-8") as stream:  # never overwrite a receipt
            stream.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        loaded = sum(o["observed"] for o in receipt["observations"])
        result = {"receipt_sha256": digest(receipt), "loaded": loaded,
                  "not_loaded": len(receipt["observations"]) - loaded}
    else:
        result = observations.import_receipt(
            args.run, args.receipt, args.out, lambda r: verify(r, args.run, args.raw, args.source))
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    main()
