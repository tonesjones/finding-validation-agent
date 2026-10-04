"""Estimate the human review queue under a passive runtime evidence policy, before building it.

  python -m fva whatif data/runs/<run>  [--key data/poc-report/final-validation-ledger.jsonl]
  -> whatif.json, whatif.md, whatif_rows.csv

Passive runtime evidence observes the app under ordinary traffic: which package versions load,
which source lines execute (coverage), which advisory functions are called, which routes and files
are deployed, and which risky options are enabled. It sends no attack traffic and never confirms.

Each finding lands in one bucket:
  auto_close  - closed by rules with cited evidence (not_applicable / valid_non_security)
  fix_ticket  - goes straight to a fix ticket as likely/confirmed, no person in the loop
  review      - a person has to decide

Rows already decided by the run keep their bucket. For rows the run left in needs_review, the answer
key's reason code says which passive signal could decide it. This uses the key as an oracle, so the
result is a ceiling for the policy, not a measurement: real numbers need real passive observations.

  optimistic   - every applicable signal is available and decisive
  conservative - coverage promotes a SAST finding only when the run already has a cited `supports`
                 argument, and advisory preconditions stay with a person (they are often not observable)
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from fva.export import score, worksheet
from fva.schemas import VerdictValue as V

AUTO_CLOSE, FIX, REVIEW = "auto_close", "fix_ticket", "review"
BUCKETS = (AUTO_CLOSE, FIX, REVIEW)
_NOW = {V.not_applicable.value: AUTO_CLOSE, V.valid_non_security.value: AUTO_CLOSE,
        V.likely.value: FIX, V.confirmed.value: FIX, V.needs_review.value: REVIEW}

_DEPLOYED = ("deployed_inventory", AUTO_CLOSE, AUTO_CLOSE)
_VERSION = ("loaded_package_version", AUTO_CLOSE, AUTO_CLOSE)
# answer-key reason code -> (passive signal, optimistic bucket, conservative bucket)
CLOSING = {
    "TEST_ONLY": _DEPLOYED, "NON_EXECUTABLE_FIXTURE": _DEPLOYED,
    "UNUSED_DEPLOYMENT_CONFIG": _DEPLOYED, "DOCUMENTATION_ONLY": _DEPLOYED,
    "VERSION_DRIFT": _VERSION, "ADVISORY_VERSION_MISMATCH": _VERSION,
    "ADVISORY_PRECONDITION_ABSENT": ("config_state_or_function_calls", AUTO_CLOSE, REVIEW),
}
# key codes for real issues: SAST needs line coverage, SCA needs the vulnerable version loaded
POSITIVE = {"RUNTIME_CONFIRMED", "RUNTIME_EXPLOITED", "BROWSER_EXECUTION_CONFIRMED", "REACHABLE_NOT_EXPLOITED"}
# key codes passive observation cannot decide -> why a person still has to look
UNDECIDABLE = {
    "MITIGATED_IN_CONTEXT": "semantic: execution shows the code runs, not whether a control mitigates it",
    "TRUSTED_SOURCE": "semantic: execution shows the code runs, not where its input comes from",
    "NO_ATTACKER_CONTROL": "semantic: execution shows the code runs, not who controls its input",
    "ACTIVE_CREDENTIAL": "credential validity is not observable passively",
    "INACTIVE_OR_NON_SECRET": "credential validity is not observable passively",
    "QUALITY_NOT_SECURITY": "stance question for the assessor, not a runtime question",
}
CONSERVATIVE_PRECONDITION = "advisory precondition kept with a person (conservative)"
NO_SUPPORT = "SAST coverage without a cited supports argument (conservative)"


def project(row: dict, key: dict | None) -> dict:
    """Current bucket, passive signal and projected buckets for one worksheet row."""
    now = _NOW[row["fva_verdict"]]
    out = {"now": now, "signal": "", "optimistic": now, "conservative": now, "why_review": ""}
    if now != REVIEW:
        return out
    code = key.get("code", "") if key else ""
    if code in CLOSING:
        out["signal"], out["optimistic"], out["conservative"] = CLOSING[code]
        if out["conservative"] == REVIEW:
            out["why_review"] = CONSERVATIVE_PRECONDITION
    elif code in POSITIVE:
        sast = row["scanner"] == "sast"
        out["signal"] = "line_coverage" if sast else "loaded_package_and_function_calls"
        out["optimistic"] = FIX
        out["conservative"] = FIX if not sast or ":supports" in row["evidence_summary"] else REVIEW
        if out["conservative"] == REVIEW:
            out["why_review"] = NO_SUPPORT
    else:
        out["why_review"] = UNDECIDABLE.get(code) or ("finding newer than the answer key" if key is None
                                                       else "no passive signal mapped to this key label")
    return out


def _share(c: Counter, n: int) -> dict:
    return {b: {"n": c[b], "share": round(c[b] / n, 3) if n else None} for b in BUCKETS}


def whatif(run_dir: Path, key_path: Path = score.DEFAULT_KEY) -> dict:
    run_dir = Path(run_dir)
    if not Path(key_path).exists():
        raise SystemExit(f"answer key not found: {key_path}")
    key, rows = score.load_key(key_path), worksheet.build(run_dir)
    out_rows = []
    for r in rows:
        k = key.get(r["source_finding_id"])
        out_rows.append({c: r[c] for c in ("source_finding_id", "scanner", "title", "cwe", "location",
                                           "fva_verdict", "evidence_summary")}
                        | {"key_classification": k["classification"] if k else ""} | project(r, k))
    n = len(out_rows)
    scenarios = {s: _share(Counter(r[s] for r in out_rows), n) for s in ("now", "optimistic", "conservative")}
    remaining = Counter(r["why_review"] or "other" for r in out_rows if r["conservative"] == REVIEW)
    risk = Counter(score.outcome(key[r["source_finding_id"]]["verdict"], r["fva_verdict"])
                   for r in out_rows if r["source_finding_id"] in key)
    metrics = {
        "rows": n, "in_key": sum(1 for r in out_rows if r["source_finding_id"] in key),
        "scenarios": scenarios,
        "signals": dict(Counter(r["signal"] for r in out_rows if r["signal"])),
        "review_reasons_conservative": dict(remaining.most_common()),
        "incorrect_demotions_now": risk["incorrect_demotion"],
        "key": str(key_path),
    }
    (run_dir / "whatif.json").write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    with open(run_dir / "whatif_rows.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out_rows[0]) if out_rows else ["source_finding_id"])
        w.writeheader()
        w.writerows(sorted(out_rows, key=lambda r: (BUCKETS.index(r["conservative"]), r["why_review"],
                                                    r["source_finding_id"])))
    (run_dir / "whatif.md").write_text(_report(metrics), encoding="utf-8")
    return {"rows": n, **{s: {b: v[b]["n"] for b in BUCKETS} for s, v in scenarios.items()}}


def _report(m: dict) -> str:
    pct = lambda x: "-" if x is None else f"{x:.1%}"
    s = m["scenarios"]
    L = ["# What-if: passive runtime evidence", "",
         f"Key: `{m['key']}`. {m['rows']} rows, {m['in_key']} in the key.", "",
         "Ceiling estimate: the answer key decides which passive signal would resolve each open finding.",
         "Real numbers need real passive observations. Passive evidence never produces `confirmed`.", "",
         "| Bucket | Now | Conservative | Optimistic |", "|---|---|---|---|"]
    L += [f"| {b} | {s['now'][b]['n']} ({pct(s['now'][b]['share'])}) | "
          f"{s['conservative'][b]['n']} ({pct(s['conservative'][b]['share'])}) | "
          f"{s['optimistic'][b]['n']} ({pct(s['optimistic'][b]['share'])}) |" for b in BUCKETS]
    L += ["", f"Incorrect demotions already in the run (carried into every scenario): "
              f"{m['incorrect_demotions_now']}.", "",
          "## Passive signals used (open findings only)", "", "| Signal | Findings |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in sorted(m["signals"].items())] or ["| none | 0 |"]
    L += ["", "## Why findings still need a person (conservative)", "", "| Reason | Findings |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in m["review_reasons_conservative"].items()] or ["| none | 0 |"]
    return "\n".join(L) + "\n"
