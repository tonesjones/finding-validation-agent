"""`python -m fva setup`: choose a model gateway and a model per tier, test them, save the settings.

Flags answer the questions up front; anything missing is asked interactively. The key stays in an environment
variable and is never written or printed.
"""
from __future__ import annotations

import json
import os

from fva import config
from fva.reasoning.model import OpenAICompatibleClient

TEST_SYSTEM = "Reply with JSON only."
TEST_USER = 'Return exactly this JSON object: {"ok": true}'


def _ask(prompt: str, default: str | None = None) -> str:
    answer = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return answer or (default or "")


def _pick(prompt: str, models: list[str], default: str | None, optional: bool = False) -> str | None:
    while True:
        answer = _ask(prompt + (" (blank to skip)" if optional else ""), default)
        if not answer and optional:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(models):
            return models[int(answer) - 1]
        if answer and (not models or answer in models):
            return answer
        print("  pick a number or a model name from the list")


def test_model(client: OpenAICompatibleClient) -> str | None:
    """None when the model answers with parseable JSON, else what went wrong."""
    try:
        reply = client.complete(TEST_SYSTEM, TEST_USER, max_tokens=50)
    except Exception as e:  # report every failure the same way, the wizard keeps going
        return f"call failed: {type(e).__name__}: {e}"
    text = reply.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        json.loads(text)
    except ValueError:
        return f"reply is not JSON: {reply[:80]!r}"
    return None


def run(args) -> dict:
    old = config.load() or {}
    old_models = old.get("models", {})
    url = args.url or _ask("Gateway URL (LiteLLM or any OpenAI-compatible endpoint)", old.get("url"))
    if not url:
        raise SystemExit("a gateway URL is required")
    default_env = old.get("key_env", config.DEFAULT_KEY_ENV)
    key_env = args.key_env or (default_env if args.url else _ask("Environment variable that holds the gateway key",
                                                                  default_env))
    if not os.environ.get(key_env):
        print(f"warning: {key_env} is not set; calls go out without a key")

    probe = OpenAICompatibleClient("", url, key_env=key_env)
    models: list[str] = []
    if not (args.senior and args.junior is not None):
        try:
            models = probe.list_models()
        except Exception as e:  # some gateways hide /models; names can still be typed
            print(f"could not list models ({type(e).__name__}); type model names instead")
        for i, name in enumerate(models, 1):
            print(f"  {i:>2}. {name}")

    senior = args.senior or _pick("Senior model (security-sensitive findings)", models, old_models.get("senior"))
    junior = args.junior if args.junior is not None else _pick(
        "Junior model (bulk, bounded findings)", models, old_models.get("junior"), optional=True)
    astra = args.astra or old_models.get("astra")
    chosen = {"senior": senior, "junior": junior or None, "astra": astra}
    chosen = {tier: name for tier, name in chosen.items() if name}

    if not args.no_test:
        for tier, name in chosen.items():
            problem = test_model(OpenAICompatibleClient(name, url, key_env=key_env))
            print(f"  {tier} {name}: {'ok' if problem is None else problem}")
            if problem:
                raise SystemExit("setup not saved; fix the model or gateway and rerun")

    cfg = {"client": "gateway", "url": url, "key_env": key_env, "models": chosen}
    print(f"saved -> {config.save(cfg)}")
    if "junior" not in chosen:
        print("no junior model: every cluster goes to the senior model")
    return cfg
