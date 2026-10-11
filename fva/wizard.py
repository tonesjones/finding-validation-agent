"""Guided start: `python -m fva` with no arguments.

Walks through models, Polaris, the source checkout and the run, then opens the report. Every answer is saved in
the settings file, so a second run offers the same choices as defaults and can go straight to the run. Tokens and
keys are never saved there; see fva/credentials.py.
"""
from __future__ import annotations

import json
import os
import re
import webbrowser
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from fva import config

ENTRYPOINT_GUESSES = ("server.ts", "server.js", "app.ts", "app.js", "index.ts", "index.js", "src/index.ts",
                      "src/index.js", "src/main.ts", "src/main.js", "frontend/src/main.ts")


def ask(prompt: str, default: str | None = None) -> str:
    answer = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return answer or (default or "")


def yes(prompt: str, default: bool = True) -> bool:
    answer = ask(f"{prompt} ({'Y/n' if default else 'y/N'})").lower()
    return default if not answer else answer.startswith("y")


def choose(prompt: str, options: list[tuple[str, str]], default: str | None = None) -> str:
    """Pick one (id, label) by number, or type an id."""
    for i, (oid, label) in enumerate(options, 1):
        print(f"  {i:>2}. {label}" + (" (current)" if oid == default else ""))
    while True:
        answer = ask(prompt, default)
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        if answer:
            return answer
        print("  pick a number from the list")


def step(n: int, title: str) -> None:
    print(f"\n== Step {n} of 4: {title} ==")


# ------------------------------------------------------------------ models


def models_step(cfg: dict) -> dict:
    step(1, "models")
    current = cfg.get("client")
    if current and not yes(f"Keep the current model setup ({_describe_models(cfg)})?"):
        current = None
    if current:
        return cfg
    kind = choose("How should FVA reach the models?", [
        ("gateway", "Company model gateway (LiteLLM or any OpenAI-compatible URL)"),
        ("codex", "Codex CLI on this machine (personal testing)")], "gateway")
    if kind == "codex":
        cfg = {**cfg, "client": "codex"}
        config.save(cfg)
        print("Codex: run `python -m fva check-isolation --client codex` once per Codex version before private code.")
        return cfg
    from fva import setup
    setup.run(SimpleNamespace(url=None, key_env=None, junior=None, senior=None, astra=None, no_test=False))
    return config.load()


def _describe_models(cfg: dict) -> str:
    if cfg.get("client") != "gateway":
        return cfg.get("client", "none")
    m = cfg.get("models", {})
    return f"gateway, senior {m.get('senior')}" + (f", junior {m['junior']}" if m.get("junior") else "")


# ------------------------------------------------------------------ polaris


def _payload(result: dict):
    """The JSON a Polaris MCP tool returned in its first text block."""
    text = result.get("content", [{}])[0].get("text", "")
    try:
        return json.loads(text)
    except ValueError:
        return {}


def named_items(payload) -> list[tuple[str, str]]:
    """(id, name) pairs anywhere in a Polaris response; shapes differ between tools."""
    found: dict[str, str] = {}

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("id"), str) and isinstance(node.get("name"), str):
                found.setdefault(node["id"], node["name"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(payload)
    return list(found.items())


def _portfolio_id(client) -> str | None:
    payload = _payload(client.call("get_portfolio_id"))
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    for key in ("portfolioId", "id"):
        if isinstance(data, dict) and isinstance(data.get(key), str):
            return data[key]
    found = named_items(payload)
    return found[0][0] if found else None


def polaris_step(cfg: dict, make_client=None) -> dict:
    step(2, "Polaris findings")
    p = dict(cfg.get("polaris", {}))
    if p.get("export") and Path(p["export"]).exists() and yes(
            f"Reuse the export in {p['export']} ({p.get('project_name', p.get('project'))})?"):
        return cfg
    if url := ask("Polaris URL", p.get("url") or os.environ.get("POLARIS_URL") or "https://poc.polaris.blackduck.com"):
        os.environ["POLARIS_URL"] = p["url"] = url
    from fva import credentials
    credentials.ensure(credentials.polaris())
    if make_client is None:
        from fva.polaris_mcp import PolarisMCP as make_client
    client = make_client()

    projects = []
    portfolio = _portfolio_id(client)
    if portfolio:
        projects = named_items(_payload(client.call("get_portfolio_projects", portfolioId=portfolio)))
    if not projects:
        print("could not list projects; paste the project id from the Polaris URL instead")
    project = choose("Project", sorted(projects, key=lambda x: x[1].lower()), p.get("project"))
    names = dict(projects)
    branches = named_items(_payload(client.call("get_branches", projectId=project)))
    branch = choose("Branch (blank: the default branch)", branches, p.get("branch")) if branches else None

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path("data/polaris-export") / f"{_slug(names.get(project, project))}-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    print(f"exporting from Polaris (read-only) -> {out}")
    from fva.polaris_mcp import export_issues
    n = export_issues(client, out, projectId=project, **({"branchId": branch} if branch else {}))
    print(f"saved {n} findings")
    p.update(project=project, project_name=names.get(project, project), branch=branch, export=str(out))
    cfg = {**cfg, "polaris": p}
    config.save(cfg)
    return cfg


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower() or "project"


# ------------------------------------------------------------------ source + profile


def guess_profile(root: Path) -> dict:
    from fva.correlation.source_pin import _git
    packs = ["node"] if (root / "package.json").exists() else []
    entry = []
    if packs:
        main = json.loads((root / "package.json").read_text(encoding="utf-8")).get("main")
        if isinstance(main, str) and (root / main).exists():
            entry.append(main)
    entry += [e for e in ENTRYPOINT_GUESSES if (root / e).exists() and e not in entry]
    commit = _git(root, "rev-parse", "HEAD")
    return {"profile_id": _slug(root.name), "name": root.name, "source_commit": commit.strip() if commit else None,
            "language_packs": packs, "deployed_surfaces": ["production_candidate", "dependency"],
            "extra_path_rules": [], "entrypoints": entry[:4]}


def source_step(cfg: dict) -> dict:
    step(3, "source code")
    s = dict(cfg.get("source", {}))
    while True:
        path = Path(ask("Path to the source checkout that was scanned", s.get("path"))).expanduser()
        if path.is_dir():
            break
        print(f"  not a folder: {path}")
    profile_file = Path(s["profile"]) if s.get("profile") and s.get("path") == str(path) else None
    if profile_file and profile_file.exists() and yes(f"Reuse the app profile in {profile_file}?"):
        return {**cfg, "source": s}

    profile = guess_profile(path)
    print(f"  commit: {profile['source_commit'] or 'not a git checkout (results cannot be pinned to a commit)'}")
    if not profile["language_packs"]:
        print("  warning: no package.json. FVA has rules for Node only, so expect few automatic decisions.")
    profile["name"] = ask("App name", profile["name"])
    entry = ask("Files where the app starts (comma-separated)", ", ".join(profile["entrypoints"]))
    profile["entrypoints"] = [e.strip() for e in entry.split(",") if e.strip()]
    if yes("Do tests or test fixtures ship to production?", default=False):
        profile["deployed_surfaces"] += ["test", "fixture"]

    from fva.schemas import DeploymentProfile
    DeploymentProfile.model_validate(profile)
    profile_file = Path("data/profiles") / f"{profile['profile_id']}.json"
    profile_file.parent.mkdir(parents=True, exist_ok=True)
    profile_file.write_text(json.dumps(profile, indent=1) + "\n", encoding="utf-8")
    print(f"  saved app profile -> {profile_file}")
    s.update(path=str(path), profile=str(profile_file))
    cfg = {**cfg, "source": s}
    config.save(cfg)
    return cfg


# ------------------------------------------------------------------ run


def run_step(cfg: dict, cli_main=None, open_report=True) -> Path | None:
    step(4, "run")
    if cli_main is None:
        from fva.__main__ import main as cli_main
    p, s = cfg["polaris"], cfg["source"]
    run_dir = Path("data/runs") / f"{datetime.now():%Y%m%d-%H%M%S}-{_slug(p.get('project_name', 'app'))}"
    print(f"  models:   {_describe_models(cfg)}\n  findings: {p['export']}\n  source:   {s['path']}\n"
          f"  output:   {run_dir}")
    smoke = yes("Try one finding group first (a quick check before the full run)?")
    if not yes("Start?"):
        return None
    findings = str(Path(p["export"]) / "page-*.json")
    argv = ["assess", "--client", cfg["client"], "--private-source", "--findings", findings, "--source", s["path"],
            "--profile-file", s["profile"]]
    if smoke:
        cli_main(argv + ["--limit", "1", "--out", f"{run_dir}-smoke"])
        if not yes("The quick check finished. Run every finding now?"):
            return None
    cli_main(argv + ["--out", str(run_dir)])
    cli_main(["triage", str(run_dir)])
    cli_main(["report", str(run_dir)])
    report = run_dir / "report.html"
    print(f"\nDone. Report: {report.resolve()}")
    if open_report and report.exists():
        webbrowser.open(report.resolve().as_uri())
    return run_dir


def main() -> None:
    from fva import credentials
    print("FVA guided start. Press Enter to keep the value in [brackets]. Ctrl+C stops at any point.\n")
    print(credentials.EXPLAINER)
    try:
        cfg = models_step(config.load() or {})
        cfg = polaris_step(cfg)
        cfg = source_step(cfg)
        run_step(cfg)
    except KeyboardInterrupt:
        print("\nstopped; answers so far are saved, run `python -m fva` to pick up again")
