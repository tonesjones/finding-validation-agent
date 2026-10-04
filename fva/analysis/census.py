"""Offline field census of saved Polaris MCP responses (list_issues pages / get_issue results).

Reports, per scanner type (sast/sca/dast) and key group (top_level, occurrence, triage, extension): how often
each key is filled, its value types, its distinct-value count, and which keys the adapter ignores. Values are
shown ONLY for the ENUM_KEYS allowlist (and only when few), so the output is safe to paste into docs.

    python -m fva census <file-or-dir>... [--out data/analysis]     # writes census.json + census.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from fva.adapters.polaris import USED_OCCURRENCE_KEYS, USED_TOP_LEVEL_KEYS, _unwrap
from fva.analysis.triage_fields import report as triage_report

ENUM_KEYS = {"cwe", "checker", "severity", "original-severity", "language", "reachability", "vulnerability-source",
             "toolType", "scanMode", "status", "dismissal-reason", "is-rapid"}
MAX_ENUM = 25
GROUPS = ("top_level", "occurrence", "triage", "extension")


def _tool_type(issue: dict, occ: dict) -> str:
    t = (issue.get("context") or {}).get("toolType")
    return str(t) if t else ("sca" if "component-name" in occ else "sast")


def _kv(issue: dict, field: str) -> dict:
    items = issue.get(field)
    return {p["key"]: p.get("value") for p in items if isinstance(p, dict) and "key" in p} \
        if isinstance(items, list) else {}


def _load(path: Path) -> list[dict]:
    if path.name == "types.json":
        return []
    try:
        items = _unwrap(json.loads(path.read_text(encoding="utf-8")))
    except Exception:  # not an MCP result: skip
        return []
    return [i for i in items if isinstance(i, dict) and "id" in i]


def _filled(v) -> bool:
    return v is not None and v != "" and v != []


def _dump(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


def _show(v) -> str:
    return (v if isinstance(v, str) else _dump(v))[:60]


def census(paths: list[Path]) -> dict:
    acc: dict[str, dict] = {}   # tool -> {"issues": n, group: {key: stat}}
    for path in paths:
        for issue in _load(Path(path)):
            occ = _kv(issue, "occurrenceProperties")
            tool = acc.setdefault(_tool_type(issue, occ), {"issues": 0, "raw": [], **{g: {} for g in GROUPS}})
            tool["issues"] += 1
            tool["raw"].append(issue)
            ctx = issue.get("context") if isinstance(issue.get("context"), dict) else {}
            fields = {"top_level": {**issue, **{f"context.{k}": ctx[k] for k in ("toolType", "scanMode") if k in ctx}},
                      "occurrence": occ, "triage": _kv(issue, "triageProperties"),
                      "extension": _kv(issue, "extensionProperties")}
            for g, kv in fields.items():
                for k, v in kv.items():
                    st = tool[g].setdefault(k, {"filled": 0, "types": set(), "enum": Counter(), "hashes": set(),
                                                "enumkey": k.rsplit(".", 1)[-1] in ENUM_KEYS})
                    st["filled"] += _filled(v)
                    st["types"].add(type(v).__name__)
                    d = _dump(v)
                    st["hashes"].add(hashlib.md5(d.encode()).hexdigest())
                    if st["enumkey"] and len(st["hashes"]) <= MAX_ENUM:
                        st["enum"][_show(v)] += 1
    out: dict = {}
    for tool in sorted(acc):
        a, n = acc[tool], acc[tool]["issues"]
        out[tool] = {"issues": n, "triage_fields": triage_report(a["raw"])}
        for g in GROUPS:
            out[tool][g] = {}
            for k in sorted(a[g]):
                st = a[g][k]
                row = {"fill": round(st["filled"] / n, 3), "types": sorted(st["types"]), "distinct": len(st["hashes"])}
                if st["enumkey"] and row["distinct"] <= MAX_ENUM:
                    row["values"] = dict(sorted(st["enum"].items(), key=lambda kv: (-kv[1], kv[0])))
                out[tool][g][k] = row
    out["dropped"] = {t: {"occurrence": sorted(set(out[t]["occurrence"]) - USED_OCCURRENCE_KEYS),
                          "top_level": sorted(k for k in out[t]["top_level"]
                                              if "." not in k and k not in USED_TOP_LEVEL_KEYS)}
                      for t in sorted(acc)}
    return out


def _cell(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(c: dict) -> str:
    lines = ["# Polaris field census", ""]
    for tool in (t for t in c if t != "dropped"):
        lines += [f"## {tool.upper()} ({c[tool]['issues']} issues)", "", "### Triage fields", "",
                  "| field | presence | issues with value |", "|---|---|---|"]
        lines += [f"| {f} | {r['presence']} | {r['issues']} |" for f, r in c[tool]["triage_fields"]["fields"].items()]
        lines.append("")
        for g in GROUPS:
            if not c[tool][g]:
                continue
            lines += [f"### {g}", "", "| key | fill | types | distinct | values |", "|---|---|---|---|---|"]
            for k, r in c[tool][g].items():
                vals = ", ".join(f"{v}: {n}" for v, n in r["values"].items()) if "values" in r else ""
                lines.append(f"| {_cell(k)} | {r['fill']:.0%} | {_cell(', '.join(r['types']))} | {r['distinct']} | {_cell(vals)} |")
            lines.append("")
        d = c["dropped"][tool]
        lines += ["### Dropped by adapter", ""]
        lines += [f"- occurrence: {', '.join(d['occurrence']) or '(none)'}", f"- top-level: {', '.join(d['top_level']) or '(none)'}", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m fva census", description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+", type=Path, help="MCP result files or directories (globbed for *.json)")
    ap.add_argument("--out", type=Path, default=Path("data/analysis"))
    a = ap.parse_args(argv)
    files = [f for p in a.paths for f in (sorted(p.glob("*.json")) if p.is_dir() else [p])]
    c = census(files)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "census.json").write_text(json.dumps(c, indent=2, sort_keys=True), encoding="utf-8")
    (a.out / "census.md").write_text(to_markdown(c), encoding="utf-8")
    counts = ", ".join(f"{t}={c[t]['issues']}" for t in c if t != "dropped") or "no issues"
    print(f"census: {counts} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
