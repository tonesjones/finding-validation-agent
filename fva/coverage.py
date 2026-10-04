"""Import coverage from the app's own tests as passive `line_executed` receipts.

Accepts a NODE_V8_COVERAGE directory or a c8/Istanbul coverage-final.json. V8 output names the
files Node ran, so a TypeScript app needs c8's source-mapped report to reach the flagged `.ts` lines.
`import` rebuilds the receipt from the same coverage and accepts it only on an exact match.
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

from fva import observations
from fva.correlation.source_pin import iter_files, pin
from fva.runtime import digest, file_digest, read_rows
from fva.schemas import FindingLocation

COLLECTOR = {"name": "coverage-import", "version": "1"}


def _input(coverage: Path) -> tuple[list[tuple[str, bytes]], str]:
    if coverage.is_dir():
        items = [(p.name, p.read_bytes()) for p in sorted(coverage.glob("coverage-*.json")) if p.is_file()]
        if not items:
            raise ValueError("coverage directory has no coverage-*.json files")
        h = hashlib.sha256()
        for name, raw in items:
            encoded = name.encode("utf-8")
            h.update(len(encoded).to_bytes(8, "big"))
            h.update(encoded)
            h.update(len(raw).to_bytes(8, "big"))
            h.update(raw)
        return items, h.hexdigest()
    raw = coverage.read_bytes()
    return [(coverage.name, raw)], hashlib.sha256(raw).hexdigest()


def _source_path(name: str, root: Path, allowed: set[str]) -> str | None:
    if name.startswith("file://"):
        uri = urlsplit(name)
        if uri.netloc not in ("", "localhost") or uri.query or uri.fragment:
            return None
        candidate = Path(url2pathname(uri.path))
    elif "://" in name:
        return None
    else:
        candidate = Path(name)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if not resolved.is_relative_to(root):
        return None
    relative = resolved.relative_to(root).as_posix()
    return relative if relative in allowed else None


def _v8_lines(raw: bytes, ranges: list[dict]) -> set[int]:
    """Apply the narrowest nested range at each character, including zero-count gaps."""
    # V8 offsets count characters, not bytes. Astral characters (two UTF-16 units) can still shift a line.
    text = raw.decode("utf-8", errors="replace").removeprefix("﻿")
    starts = [0]
    ends = []
    offset = 0
    for line in text.splitlines(keepends=True):
        content_end = offset + len(line.rstrip("\r\n"))
        ends.append(content_end)
        offset += len(line)
        starts.append(offset)
    if not ends:
        return set()

    events = []
    for index, item in enumerate(ranges):
        start, end, count = item["startOffset"], item["endOffset"], item["count"]
        if not (0 <= start < end <= len(text)):
            raise ValueError("V8 range lies outside its pinned source file")
        events.append((start, 1, index, end - start, count))
        events.append((end, 0, index, end - start, count))
    events.sort()
    active = set()
    narrowest = []
    covered = set()
    for n, (position, kind, index, span, count) in enumerate(events):
        if kind:
            active.add(index)
            heapq.heappush(narrowest, (span, index, count))
        else:
            active.discard(index)
        if n + 1 == len(events):
            break
        next_position = events[n + 1][0]
        while narrowest and narrowest[0][1] not in active:
            heapq.heappop(narrowest)
        if not narrowest or narrowest[0][2] <= 0 or position == next_position:
            continue
        line = bisect_right(starts, position) - 1
        while line < len(ends) and starts[line] < next_position:
            if position < ends[line] and next_position > starts[line]:
                covered.add(line + 1)
            line += 1
    return covered


def _istanbul_lines(entry: dict) -> set[int]:
    covered = set()
    for key, span in entry["statementMap"].items():
        if entry["s"].get(key, 0) <= 0:
            continue
        first = span["start"]["line"]
        last = span["end"]["line"] - (span["end"].get("column") == 0)
        covered.update(range(first, last + 1))
    return covered


def build_receipt(run: Path, coverage: Path, source: Path, exercise: str, collected_at: str | None = None) -> dict:
    root = source.resolve()
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    if pin(root).content_sha256 != summary["source_content_sha256"]:
        raise ValueError("source checkout does not match the run's content hash")
    allowed = {name for name, _ in iter_files(root)}
    items, raw_hash = _input(coverage)
    instrumented: set[str] = set()
    covered: dict[str, set[int]] = {}
    for name, raw in items:
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get("result"), list):
            for script in data["result"]:
                path = _source_path(script["url"], root, allowed)
                if path is None:
                    continue
                instrumented.add(path)
                ranges = [r for function in script["functions"] for r in function["ranges"]]
                covered.setdefault(path, set()).update(_v8_lines((root / path).read_bytes(), ranges))
        elif isinstance(data, dict):
            for key, entry in data.items():
                path = _source_path(entry.get("path", key), root, allowed)
                if path is None:
                    continue
                instrumented.add(path)
                covered.setdefault(path, set()).update(_istanbul_lines(entry))
        else:
            raise ValueError(f"unsupported coverage format in {name}")

    result = []
    for row in read_rows(run / "findings.jsonl"):
        if row.get("finding_type") != "sast" or not row.get("path") or not row.get("line"):
            continue
        location = FindingLocation(path=row["path"], start_line=row["line"])
        if location.path not in instrumented:
            continue
        result.append({"kind": "line_executed", "finding_ids": [row["finding_id"]],
                       "observed": location.start_line in covered[location.path],
                       "subject": {"path": location.path, "line": location.start_line}})
    if not result:
        raise ValueError("no SAST finding lines have coverage data; no receipt written")
    data = {"format": observations.FORMAT, "profile_id": summary["profile"],
            "source_content_sha256": summary["source_content_sha256"],
            "findings_sha256": file_digest(run / "findings.jsonl"),
            "collector": COLLECTOR, "exercise": exercise, "raw_file": {"name": coverage.name, "sha256": raw_hash},
            "collected_at": collected_at or datetime.now(timezone.utc).isoformat(), "observations": result}
    observations.bind_run(observations.Receipt.model_validate(data), run)
    return data


def verify(receipt: dict, run: Path, coverage: Path, source: Path) -> None:
    if receipt.get("collector") != COLLECTOR:
        raise ValueError("receipt was not written by this collector")
    rebuilt = build_receipt(run, coverage, source, receipt["exercise"], receipt["collected_at"])
    if digest(rebuilt) != digest(receipt):
        raise ValueError("receipt does not match its raw coverage")


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(prog="python -m fva coverage", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    rec = commands.add_parser("receipt", help="map coverage of the app's own tests to a receipt")
    imp = commands.add_parser("import", help="verify a receipt against its coverage into a new run")
    for p in (rec, imp):
        p.add_argument("run", type=Path)
        p.add_argument("--coverage", type=Path, required=True,
                       help="NODE_V8_COVERAGE directory or c8/Istanbul coverage-final.json")
        p.add_argument("--source", type=Path, required=True)
    rec.add_argument("--exercise", required=True, help='how the app ran, e.g. "npm test"')
    rec.add_argument("--out", type=Path, required=True)
    imp.add_argument("receipt", type=Path)
    imp.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "receipt":
        receipt = build_receipt(args.run, args.coverage, args.source, args.exercise)
        with args.out.open("x", encoding="utf-8") as stream:  # never overwrite a receipt
            stream.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        executed = sum(o["observed"] for o in receipt["observations"])
        result = {"receipt_sha256": digest(receipt), "executed": executed,
                  "not_executed": len(receipt["observations"]) - executed}
    else:
        result = observations.import_receipt(
            args.run, args.receipt, args.out, lambda r: verify(r, args.run, args.coverage, args.source))
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    main()
