"""Score a run's worksheet against an answer key (the Juice Shop PoC ledger), with no hand review.

  python -m fva score data/runs/<run>  [--key data/poc-report/final-validation-ledger.jsonl]
  -> score.json (metrics), score.md (readable report), score_rows.csv (every row with its outcome)

Rows are matched by Polaris issue id (worksheet `source_finding_id` == ledger `candidate_id`). The ledger's
`classification` maps to a reason code and verdict through `reason_codes.LEGACY_POC_MAP`. The PoC had runtime
tests and fva (without runtime probes) does not, so PoC `confirmed` vs fva `likely` is scored as its own outcome.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from fva import reason_codes, triage
from fva.export import worksheet
from fva.schemas import VerdictValue as V

DEFAULT_KEY = Path("data/poc-report/final-validation-ledger.jsonl")
_POSITIVE = {V.confirmed.value, V.likely.value}
_CLEARED = {V.not_applicable.value, V.valid_non_security.value}

# outcome -> one-line meaning, in report order
OUTCOMES = {
    "agree": "Same verdict as the answer key.",
    "agree_static": "Key says confirmed (proven at runtime); fva says likely. Best possible without runtime tests.",
    "unresolved": "fva says needs_review; a person still has to look.",
    "incorrect_demotion": "Key says the issue is real or open; fva cleared it. The dangerous error.",
    "over_flag": "Key cleared it; fva says likely or confirmed. Costs review time, not safety.",
    "wrong_clearance_kind": "Both cleared it, but one says not applicable and the other not security.",
    "other_mismatch": "Any other disagreement.",
    "not_in_key": "Finding is newer than the answer key; not scored.",
}


def outcome(expected: str | None, got: str) -> str:
    if expected is None:
        return "not_in_key"
    if got == expected:
        return "agree"
    if expected == V.confirmed.value and got == V.likely.value:
        return "agree_static"
    if got == V.needs_review.value:
        return "unresolved"
    if got in _CLEARED and expected not in _CLEARED:
        return "incorrect_demotion"
    if got in _POSITIVE and expected in _CLEARED:
        return "over_flag"
    if got in _CLEARED and expected in _CLEARED:
        return "wrong_clearance_kind"
    return "other_mismatch"


def load_key(path: Path) -> dict[str, dict]:
    key = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if "case_id" in r:
                if not r.get("rationale", "").strip():
                    raise ValueError("explicit gold rows require a rationale")
                case_id = r["case_id"]
                value = {**r, "verdict": V(r["expected_verdict"]).value, "code": "",
                         "classification": r["rationale"]}
            else:
                code = reason_codes.LEGACY_POC_MAP[r["classification"]]
                case_id = r["candidate_id"]
                value = {"verdict": reason_codes.verdict_for(code).value, "code": code,
                         "classification": r["classification"]}
            if case_id in key:
                raise ValueError(f"duplicate gold id: {case_id}")
            key[case_id] = value
    return key


def _tiers(run_dir: Path) -> dict[str, str]:
    """finding_id -> model tier that gave the final answer ('rules' when no model was called)."""
    out = {}
    for a in worksheet._read_jsonl(run_dir / "assessments.jsonl"):
        for fid in a.get("finding_ids") or []:
            out[fid] = a.get("tier") or "error"
    return out


def score(run_dir: Path, key_path: Path = DEFAULT_KEY) -> dict:
    run_dir = Path(run_dir)
    if not Path(key_path).exists():
        raise SystemExit(f"answer key not found: {key_path}")
    key, tiers = load_key(key_path), _tiers(run_dir)
    rows = worksheet.build(run_dir)
    routes = {t["finding_id"]: t["route"] for t in triage.build(run_dir)}
    scored, by = [], {"verdict": {}, "scanner": {}, "tier": {}, "route": {}}
    matrix: dict[str, Counter] = {}
    for r in rows:
        k = key.get(r["source_finding_id"])
        exp = k["verdict"] if k else None
        o = outcome(exp, r["fva_verdict"])
        tier = tiers.get(r["finding_id"], "rules")
        route = routes.get(r["finding_id"], triage.REVIEW)
        code_match = bool(k) and o == "agree" and k["code"] in r["reason_codes"].split()
        scored.append({**{c: r[c] for c in ("source_finding_id", "scanner", "title", "location", "fva_verdict",
                                            "reason_codes", "evidence_summary")},
                       "tier": tier, "route": route, "key_verdict": exp or "", "key_classification": k["classification"] if k else "",
                       "outcome": o, "reason_code_match": "yes" if code_match else ""})
        if exp:
            matrix.setdefault(exp, Counter())[r["fva_verdict"]] += 1
        for dim, val in (("verdict", exp or "not_in_key"), ("scanner", r["scanner"]), ("tier", tier), ("route", route)):
            by[dim].setdefault(val, Counter())[o] += 1
    total = Counter(s["outcome"] for s in scored)
    n = sum(v for o, v in total.items() if o != "not_in_key")
    queue = sum(1 for r in rows if r["fva_verdict"] in (V.needs_review.value, V.likely.value, V.confirmed.value))
    auto = [s for s in scored if s["route"] == triage.AUTO]
    auto_keyed = [s for s in auto if s["outcome"] != "not_in_key"]
    metrics = {
        "rows": len(rows), "scored": n, "outcomes": dict(total),
        "auto_share": round(len(auto) / len(rows), 3) if rows else None,
        "auto_agreement": round(sum(s["outcome"] in ("agree", "agree_static") for s in auto_keyed)
                                / len(auto_keyed), 3) if auto_keyed else None,
        "auto_incorrect_demotions": sum(s["outcome"] == "incorrect_demotion" for s in auto),
        "agreement": round((total["agree"] + total["agree_static"]) / n, 3) if n else None,
        "strict_agreement": round(total["agree"] / n, 3) if n else None,
        "incorrect_demotions": total["incorrect_demotion"],
        "unresolved_rate": round(total["unresolved"] / n, 3) if n else None,
        "queue_reduction": round(1 - queue / len(rows), 3) if rows else None,
        "reason_code_match_on_agree": sum(1 for s in scored if s["reason_code_match"]),
        "confusion": {e: dict(c) for e, c in sorted(matrix.items())},
        "by": {d: {k: dict(c) for k, c in sorted(v.items())} for d, v in by.items()},
        "key": str(key_path),
    }
    (run_dir / "score.json").write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    with open(run_dir / "score_rows.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(scored[0]) if scored else ["source_finding_id"])
        w.writeheader()
        w.writerows(sorted(scored, key=lambda s: (list(OUTCOMES).index(s["outcome"]), s["source_finding_id"])))
    (run_dir / "score.md").write_text(_report(metrics, scored), encoding="utf-8")
    return {k: metrics[k] for k in ("rows", "scored", "agreement", "strict_agreement", "incorrect_demotions",
                                    "unresolved_rate", "queue_reduction", "outcomes", "auto_share",
                                    "auto_agreement", "auto_incorrect_demotions")}


def _pct(x) -> str:
    return "-" if x is None else f"{x:.1%}"


def _report(m: dict, scored: list[dict]) -> str:
    verdicts = [v.value for v in (V.confirmed, V.likely, V.needs_review, V.valid_non_security, V.not_applicable)]
    L = ["# Score against the answer key", "",
         f"Key: `{m['key']}`. {m['rows']} rows, {m['scored']} scored.", "",
         "| Metric | Value |", "|---|---|",
         f"| Agreement (agree + agree_static) | {_pct(m['agreement'])} |",
         f"| Strict agreement | {_pct(m['strict_agreement'])} |",
         f"| Incorrect demotions | {m['incorrect_demotions']} |",
         f"| Unresolved (needs_review) | {_pct(m['unresolved_rate'])} |",
         f"| Queue reduction | {_pct(m['queue_reduction'])} |",
         f"| Reason code also matches (of agree) | {m['reason_code_match_on_agree']} |", "",
         "## Triage routing", "", "| Metric | Value |", "|---|---|",
         f"| Auto share | {_pct(m['auto_share'])} |",
         f"| Auto agreement | {_pct(m['auto_agreement'])} |",
         f"| Auto incorrect demotions | {m['auto_incorrect_demotions']} |", "",
         "## Outcomes", "", "| Outcome | Count | Meaning |", "|---|---|---|"]
    L += [f"| {o} | {m['outcomes'].get(o, 0)} | {d} |" for o, d in OUTCOMES.items()]
    L += ["", "## Confusion (rows: answer key, columns: fva)", "",
          "| key \\ fva | " + " | ".join(verdicts) + " |", "|---" * (len(verdicts) + 1) + "|"]
    for e in verdicts:
        if e in m["confusion"]:
            L.append(f"| {e} | " + " | ".join(str(m["confusion"][e].get(v, 0)) for v in verdicts) + " |")
    for dim in ("tier", "scanner", "route"):
        L += ["", f"## By {dim}", "", f"| {dim} | " + " | ".join(OUTCOMES) + " |", "|---" * (len(OUTCOMES) + 1) + "|"]
        L += [f"| {k} | " + " | ".join(str(c.get(o, 0)) for o in OUTCOMES) + " |" for k, c in m["by"][dim].items()]
    bad = [s for s in scored if s["outcome"] == "incorrect_demotion"]
    L += ["", f"## Incorrect demotions ({len(bad)}): check these first", ""]
    L += [f"- `{s['source_finding_id']}` {s['title']} at {s['location']}: key {s['key_classification']}, "
          f"fva {s['fva_verdict']} ({s['reason_codes']}; tier {s['tier']})" for s in bad] or ["None."]
    return "\n".join(L) + "\n"
