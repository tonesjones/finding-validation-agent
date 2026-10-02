"""Offline "correlation value" analysis: do candidate join keys between findings carry decision value?

  python -m fva correlation-value [--findings "data/polaris-export/page-*.json"]
        [--key data/poc-report/final-validation-ledger.jsonl] [--source <checkout>] [--out data/analysis]
  -> correlation-value.json + correlation-value.md (aggregates only: no ids, paths, package names or advisories)

Findings are saved Polaris MCP responses; the answer key is the hand-validated PoC ledger (local only).
`real` = key verdict in {confirmed, likely, needs_review}; `cleared` = {not_applicable, valid_non_security}.
Per key, over unordered finding pairs where both sides are in the key:
  coherence  share of pairs where both are real or both are cleared
  lift       P(B real | A real) / P(B real) over ordered pairs (A, B); base rate is per B's tool type;
             > 1: knowing A is real raises the odds that B is real
Coverage x lift with low fan-out is what makes a key useful. DAST issues are counted and ignored.
"""
from __future__ import annotations

import argparse
import glob
import json
import re
from collections import defaultdict
from itertools import product
from pathlib import Path

REAL = {"confirmed", "likely", "needs_review"}
CLEARED = {"not_applicable", "valid_non_security"}
DEFAULT_FINDINGS = "data/polaris-export/page-*.json"
DEFAULT_KEY = "data/poc-report/final-validation-ledger.jsonl"
DEFAULT_OUT = "data/analysis"
WINDOW = 15
_STOP = {"function", "return", "while", "catch", "switch", "require", "import", "this", "that", "with"}
_ZERO = re.compile(r"^0*$")


# ----------------------------------------------------------------------------------------------
# loading
# ----------------------------------------------------------------------------------------------
def _load(paths):
    """-> (records, findings by sid). Re-reads raw issues in load_mcp's (sorted) file order."""
    from fva.adapters import polaris
    paths = sorted(Path(p) for p in ([paths] if isinstance(paths, (str, Path)) else paths))
    if not paths:
        return [], {}
    _, findings = polaris.load_mcp(paths)
    tf = paths[0].parent / "types.json"
    types = json.loads(tf.read_text(encoding="utf-8")) if tf.exists() else {}
    raw = [i for p in paths for i in polaris._unwrap(json.loads(p.read_text(encoding="utf-8")))]
    assert len(raw) == len(findings)
    recs, by_sid = [], {}
    for issue, f in zip(raw, findings):
        op = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}
        alt = ((issue.get("type") or {}).get("altName")
               or (types.get(issue.get("weaknessId")) or {}).get("altName") or "")
        loc, pkg = f.location, f.package
        recs.append({
            "sid": f.source_finding_id, "tool": f.finding_type.value, "cwe": set(f.cwe),
            "path": loc.path if loc else None, "line": loc.start_line if loc else None,
            "function": loc.function if loc else None,
            "package": (pkg.name, pkg.version) if pkg else None, "advisory": pkg.advisory_id if pkg else None,
            "linked": op.get("linked-vulnerability-id"), "md5": op.get("source-fragment-md5"),
            "tech": op.get("technical-description"), "risk": op.get("base-risk-score"),
            "severity": f.severity.value, "type_family": alt.split(":")[0] or None,
            "reachability": issue.get("reachability")})
        by_sid[f.source_finding_id] = f
    return recs, by_sid


def load_records(paths) -> list[dict]:
    return _load(paths)[0]


# ----------------------------------------------------------------------------------------------
# candidate keys: each yields unordered pairs (sast, sca) / sorted (a, b)
# ----------------------------------------------------------------------------------------------
def _bucket(recs, fn):
    out = defaultdict(set)
    for r in recs:
        for k in fn(r):
            out[k].add(r["sid"])
    return out


def _cross(a, b, fn):
    """Bucket sast `a` and sca `b` on fn (iterable of keys per record); pair within buckets."""
    ba, bb, out = _bucket(a, fn), _bucket(b, fn), set()
    for k in ba.keys() & bb.keys():
        out.update(product(ba[k], bb[k]))
    return out


def _within(recs, fn):
    out = set()
    for ids in _bucket(recs, fn).values():
        s = sorted(ids)
        out.update((x, y) for i, x in enumerate(s) for y in s[i + 1:])
    return out


def _idents(tech: str | None) -> set[str]:
    t = tech or ""
    toks = {m.strip() for m in re.findall(r"`([^`]+)`", t)}
    for m in re.findall(r"[\w./-]+\.(?:js|ts)\b", t):
        toks.update((m, m.rsplit("/", 1)[-1]))
    toks.update(re.findall(r"([A-Za-z_$][\w$]*)\(", t))
    toks.update(m for tok in list(toks) for m in re.findall(r"([A-Za-z_$][\w$]*)\(", tok))
    return {x.lower() for x in toks if len(x) >= 4 and x.lower() not in _STOP}


def _near_sink(sast, sca, source):
    idx, ids, win = source["idx"], {r["sid"]: _idents(r["tech"]) for r in sca}, {}
    for r in sast:
        if r["path"] is None or r["line"] is None:
            continue
        rel, _ = idx.resolve(r["path"])
        if rel is None:
            continue
        lines = idx.lines(rel)
        win[r["sid"]] = "\n".join(lines[max(0, r["line"] - 1 - WINDOW): r["line"] + WINDOW]).lower()
    return {(s, c) for c, toks in ids.items() if toks for s, text in win.items() if any(t in text for t in toks)}


def _shipped(sast, sca, source):
    from fva.correlation import package_link
    fs, out = source["findings"], set()
    for a in sca:
        for b in sast:
            fa, fb = fs.get(a["sid"]), fs.get(b["sid"])
            if fa and fb and package_link.link(fa, fb, source["graph"], source["profile"]):
                out.add((b["sid"], a["sid"]))
    return out


def _alias(sca):
    adv, lnk = _bucket(sca, lambda r: [r["advisory"]] if r["advisory"] else []), \
        _bucket(sca, lambda r: [r["linked"]] if r["linked"] else [])
    out = set()
    for r in sca:
        p = set()
        if r["advisory"]:
            p |= lnk.get(r["advisory"], set())
        if r["linked"]:
            p |= adv.get(r["linked"], set()) | lnk.get(r["linked"], set())
        out.update(tuple(sorted((r["sid"], x))) for x in p if x != r["sid"])
    return out


def _md5(r):
    return [r["md5"]] if r["md5"] and not _ZERO.match(str(r["md5"])) else []


# name -> (tool types it relates, needs source, fn(sast, sca, source) -> set of pairs)
KEYS = {
    "same_cwe": ("sast-sca", False, lambda a, c, s: _cross(a, c, lambda r: r["cwe"])),
    "same_type_family": ("sast-sca", False, lambda a, c, s: _cross(a, c, lambda r: [r["type_family"]] if r["type_family"] else [])),
    "shipped_import_same_file": ("sast-sca", True, lambda a, c, s: _shipped(a, c, s)),
    "advisory_symbol_near_sink": ("sast-sca", True, lambda a, c, s: _near_sink(a, c, s)),
    "same_path_line": ("sast-sast", False, lambda a, c, s: _within(
        a, lambda r: [(r["path"], r["line"])] if r["path"] and r["line"] is not None else [])),
    "same_function": ("sast-sast", False, lambda a, c, s: _within(
        a, lambda r: [r["function"]] if r["function"] not in (None, "", "unknown") else [])),
    "same_fragment_md5": ("sast-sast", False, lambda a, c, s: _within(a, _md5)),
    "same_component_version": ("sca-sca", False, lambda a, c, s: _within(
        c, lambda r: [r["package"]] if r["package"] and r["package"][0] else [])),
    "cve_bdsa_alias": ("sca-sca", False, lambda a, c, s: _alias(c)),
}


# ----------------------------------------------------------------------------------------------
# metrics
# ----------------------------------------------------------------------------------------------
def _r(x):
    return None if x is None else round(x, 4)


def _cls(verdict):
    return "real" if verdict in REAL else "cleared" if verdict in CLEARED else "other"


def _metrics(pairs, cls, verdict, tool, base, denom):
    covered, n = set(), len(pairs)
    for a, b in pairs:
        covered.update((a, b))
    coh = sum(cls[a] == cls[b] != "other" for a, b in pairs)
    agree = sum(verdict[a] == verdict[b] for a, b in pairs)
    n_cond = hit = 0
    expected = 0.0
    for a, b in (p for pr in pairs for p in (pr, pr[::-1])):
        if cls[a] == "real":
            n_cond += 1
            hit += cls[b] == "real"
            expected += base.get(tool[b]) or 0.0
    return {"pairs": n, "findings_covered": len(covered), "coverage": _r(len(covered) / denom) if denom else None,
            "mean_fanout": _r(2 * n / len(covered)) if covered else None,
            "coherence": _r(coh / n) if n else None, "verdict_agreement": _r(agree / n) if n else None,
            "lift": _r(hit / expected) if expected else None, "n_cond": n_cond}


def _table(items, label, cls):
    out = defaultdict(lambda: {"n": 0, "real": 0, "cleared": 0})
    for r in items:
        row = out[label(r)]
        row["n"] += 1
        if cls[r["sid"]] in ("real", "cleared"):
            row[cls[r["sid"]]] += 1
    for row in out.values():
        row["real_rate"] = _r(row["real"] / row["n"])
    return dict(sorted(out.items(), key=lambda kv: str(kv[0])))


def _bucket_risk(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "none"
    return "<40" if v < 40 else "40-59" if v < 60 else "60-79" if v < 80 else ">=80"


def analyze(records: list[dict], key: dict[str, dict], *, source: dict | None = None) -> dict:
    dast = sum(r["tool"] == "dast" for r in records)
    recs = [r for r in records if r["tool"] in ("sast", "sca")]
    scored = [r for r in recs if r["sid"] in key]
    verdict = {r["sid"]: key[r["sid"]]["verdict"] for r in scored}
    cls = {s: _cls(v) for s, v in verdict.items()}
    tool = {r["sid"]: r["tool"] for r in scored}
    sast, sca = [r for r in scored if r["tool"] == "sast"], [r for r in scored if r["tool"] == "sca"]
    n_by = {"sast": len(sast), "sca": len(sca)}
    base = {t: (sum(cls[r["sid"]] == "real" for r in rs) / len(rs)) if rs else None
            for t, rs in (("sast", sast), ("sca", sca))}
    denoms = {"sast-sca": len(scored), "sast-sast": n_by["sast"], "sca-sca": n_by["sca"]}
    keys = {}
    for name, (kind, needs_src, fn) in KEYS.items():
        if needs_src and source is None:
            keys[name] = {"skipped": "needs --source"}
            continue
        pairs = {p for p in fn(sast, sca, source) if p[0] in key and p[1] in key and p[0] != p[1]}
        keys[name] = {"between": kind, **_metrics(pairs, cls, verdict, tool, base, denoms[kind])}
    cnt = lambda rs: {"n": len(rs), "real": sum(cls[r["sid"]] == "real" for r in rs),
                      "cleared": sum(cls[r["sid"]] == "cleared" for r in rs)}
    return {
        "meta": {"records": len(records), "dast_ignored": dast, "sast": len([r for r in recs if r["tool"] == "sast"]),
                 "sca": len([r for r in recs if r["tool"] == "sca"]), "scored_sast": cnt(sast), "scored_sca": cnt(sca),
                 "base_rate_real": {t: _r(v) for t, v in base.items()}, "source": source is not None},
        "keys": keys,
        "signals": {
            "sca_reachability": _table(sca, lambda r: r["reachability"] or "none", cls),
            "risk_score": {"sast": _table(sast, lambda r: _bucket_risk(r["risk"]), cls),
                           "sca": _table(sca, lambda r: _bucket_risk(r["risk"]), cls)},
            "severity": {"sast": _table(sast, lambda r: r["severity"], cls),
                         "sca": _table(sca, lambda r: r["severity"], cls)}},
    }


# ----------------------------------------------------------------------------------------------
# output
# ----------------------------------------------------------------------------------------------
_HEAD = """# Correlation value

Do candidate join keys between findings carry decision value, scored against the hand-validated answer key?

- **real** = key verdict confirmed, likely or needs_review. **cleared** = not_applicable or valid_non_security.
- Only pairs where both findings are in the answer key are counted. Pairs are unordered and de-duplicated.
- **coverage** = findings in at least one pair / scored findings of the relevant tool types.
  **mean_fanout** = mean partners per covered finding.
- **coherence** = share of pairs where both are real or both are cleared.
  **verdict_agreement** = share of pairs with identical key verdicts.
- **lift** = P(B real | A real) / P(B real) over ordered pairs; the base rate is that of B's tool type.
  Lift > 1 means knowing A is real raises the odds that B is real. `n_cond` = ordered pairs with A real.
- A useful key has high coverage x lift with low fan-out.
"""


def _f(x):
    return "-" if x is None else f"{x:g}"


def to_markdown(result: dict) -> str:
    m = result["meta"]
    out = [_HEAD, f"Records: {m['records']} ({m['sast']} sast, {m['sca']} sca, {m['dast_ignored']} dast ignored). "
           f"Scored sast: {m['scored_sast']['n']} ({m['scored_sast']['real']} real, {m['scored_sast']['cleared']} cleared); "
           f"scored sca: {m['scored_sca']['n']} ({m['scored_sca']['real']} real, {m['scored_sca']['cleared']} cleared). "
           f"Base rate real: sast {_f(m['base_rate_real']['sast'])}, sca {_f(m['base_rate_real']['sca'])}.\n",
           "## Candidate keys\n", "| key | between | pairs | covered | coverage | fanout | coherence | agreement | lift | n_cond |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for name, k in result["keys"].items():
        if "skipped" in k:
            out.append(f"| {name} | - | {k['skipped']} | | | | | | | |")
        else:
            out.append(f"| {name} | {k['between']} | {k['pairs']} | {k['findings_covered']} | {_f(k['coverage'])} | "
                       f"{_f(k['mean_fanout'])} | {_f(k['coherence'])} | {_f(k['verdict_agreement'])} | "
                       f"{_f(k['lift'])} | {k['n_cond']} |")

    def tbl(title, t):
        out.extend(["", f"### {title}", "", "| value | n | real | cleared | real_rate |", "|---|---|---|---|---|"])
        out.extend(f"| {v} | {r['n']} | {r['real']} | {r['cleared']} | {_f(r['real_rate'])} |" for v, r in t.items())

    s = result["signals"]
    out.append("\n## Polaris signals")
    tbl("SCA reachability", s["sca_reachability"])
    for tl in ("sast", "sca"):
        tbl(f"Base risk score ({tl})", s["risk_score"][tl])
    for tl in ("sast", "sca"):
        tbl(f"Severity ({tl})", s["severity"][tl])
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m fva correlation-value", description=__doc__.split("\n")[0])
    ap.add_argument("--findings", default=DEFAULT_FINDINGS, help="glob of saved Polaris MCP responses")
    ap.add_argument("--key", default=DEFAULT_KEY)
    ap.add_argument("--source", help="source checkout; enables the source-based keys")
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    if not Path(a.key).exists():
        raise SystemExit(f"answer key not found: {a.key} (the PoC ledger exists only locally)")
    paths = sorted(glob.glob(a.findings))
    if not paths:
        raise SystemExit(f"no findings files match: {a.findings}")
    from fva.export.score import load_key
    key = load_key(Path(a.key))
    records, findings = _load(paths)
    source = None
    if a.source:
        from fva.adapters.poc_ledger import JUICESHOP_PROFILE
        from fva.correlation import reachability, source_pin
        from fva.correlation.locate import SourceIndex
        root = Path(a.source)
        files = [r for r, _ in source_pin.iter_files(root)]
        source = {"idx": SourceIndex(root, files), "profile": JUICESHOP_PROFILE, "findings": findings,
                  "graph": reachability.build_graph(root, files, JUICESHOP_PROFILE)}
    res = analyze(records, key, source=source)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "correlation-value.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (out / "correlation-value.md").write_text(to_markdown(res), encoding="utf-8")
    ran = [k for k, v in res["keys"].items() if "skipped" not in v]
    best = max((k for k in ran if res["keys"][k]["lift"] is not None), key=lambda k: res["keys"][k]["lift"], default=None)
    print(f"correlation-value: {res['meta']['sast']} sast, {res['meta']['sca']} sca, {len(ran)}/{len(KEYS)} keys; "
          f"top lift: {best or 'none'} {res['keys'][best]['lift'] if best else ''}; wrote {out}")


if __name__ == "__main__":
    main()
