"""Dollar estimate for Codex model calls from exact token usage.

Prices are USD per 1M tokens, keyed by the model name the CLI reported. Assumption (OpenAI Responses
convention): `input_tokens` includes `cached_input_tokens`, and `output_tokens` already includes
`reasoning_output_tokens`, so reasoning tokens are recorded but never added again.
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_PRICES = {
    "gpt-6-sol": {"input": 2.00, "cached_input": 0.20, "output": 10.00},
    "gpt-6-luna": {"input": 0.10, "cached_input": 0.01, "output": 0.50},
}


def load_prices(path: Path) -> dict:
    prices = json.loads(Path(path).read_text(encoding="utf-8"))
    for model, row in prices.items():
        if not isinstance(row, dict) or not {"input", "cached_input", "output"} <= row.keys():
            raise ValueError(f"prices for {model!r} need input, cached_input and output")
    return prices


def cost(usage: dict | None, model: str | None, prices: dict | None = None) -> float | None:
    """USD for one call, or None when there is no usage or the model has no price."""
    prices = DEFAULT_PRICES if prices is None else prices
    if not usage or not model:
        return None
    row = prices.get(model) or prices.get(model.rsplit(":", 1)[-1])
    if row is None:
        return None
    total, cached, out = (usage.get(k, 0) for k in ("input_tokens", "cached_input_tokens", "output_tokens"))
    return ((total - cached) * row["input"] + cached * row["cached_input"] + out * row["output"]) / 1e6


def new_cost() -> dict:
    return {"fresh_calls": 0, "input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0, "usd": 0.0,
            "calls_without_usage": 0, "unpriced_calls": 0, "usd_when_first_made": 0.0}


def add_call(c: dict, attempt: dict, prices: dict | None = None) -> None:
    """Fold one routing attempt into a cost block. Only fresh calls count toward `usd`."""
    usage = attempt.get("usage")
    usd = cost(usage, attempt.get("agent_model"), prices)
    if attempt["cached"]:
        c["usd_when_first_made"] += usd or 0.0
        return
    c["fresh_calls"] += 1
    if not usage:
        c["calls_without_usage"] += 1
        return
    for k in ("input_tokens", "cached_input_tokens", "output_tokens"):
        c[k] += usage.get(k, 0)
    if usd is None:
        c["unpriced_calls"] += 1
    else:
        c["usd"] += usd


def finish(c: dict) -> dict:
    c["usd"], c["usd_when_first_made"] = round(c["usd"], 6), round(c["usd_when_first_made"], 6)
    return c


def summary_line(c: dict) -> str:
    return (f"cost: {c['fresh_calls']} fresh call(s), ~${c['usd']:.4f}"
            f" ({c['calls_without_usage']} without usage, {c['unpriced_calls']} unpriced)")
