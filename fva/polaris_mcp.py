"""Minimal read-only client for the Polaris Issue Management MCP server.

Credentials come from the environment (never from code or committed config):
  POLARIS_URL            e.g. https://poc.polaris.blackduck.com   (default)
  POLARIS_ACCESS_TOKEN   Polaris access token
Falls back to data/.polaris-token (git-ignored) if the variable is unset.

Capture raw sample responses (for adapter fixtures):
  python -m fva.polaris_mcp sample --project <projectId> --issue <sastIssueId> --issue <scaIssueId>
Writes data/polaris-samples/*.json. The token is never printed or saved.

What can this server return? (tool schemas, tool types present, maximal-detail sample issues):
  python -m fva.polaris_mcp inventory [--project <projectId> [--branch <branchId>]] [--samples 3] [--max-issues 2000]
Writes raw responses to data/polaris-inventory/raw/ (local only, contains real ids) and a sanitized
inventory.json / inventory.md (no names, ids, URLs; projects shown as sha256(id)[:8]).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

READ_ONLY_TOOLS = {"list_issues", "list_component_versions", "get_issue", "get_portfolio_id", "get_portfolio_applications",
                   "get_portfolio_projects", "get_branches", "get_application_dashboard",
                   "get_project_dashboard", "get_application_entitlements_info"}


class PolarisMCP:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.url = (base_url or os.environ.get("POLARIS_URL") or "https://poc.polaris.blackduck.com").rstrip("/") + "/api/mcp"
        tok = token or os.environ.get("POLARIS_ACCESS_TOKEN")
        if not tok:
            f = Path("data/.polaris-token")
            tok = f.read_text(encoding="utf-8").strip() if f.exists() else None
        if not tok:
            raise SystemExit("Set POLARIS_ACCESS_TOKEN (or put the token in data/.polaris-token)")
        self._token, self._sid, self._id = tok, None, 0
        self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "fva", "version": "0.2"}})
        self._rpc("notifications/initialized", notify=True)

    def _rpc(self, method, params=None, notify=False):
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            self._id += 1
            body["id"] = self._id
        h = {"Api-Token": self._token, "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self._sid:
            h["Mcp-Session-Id"] = self._sid
        req = urllib.request.Request(self.url, json.dumps(body).encode(), h)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self._sid = r.headers.get("Mcp-Session-Id") or self._sid
                raw = r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise SystemExit(f"Polaris MCP {method}: HTTP {e.code} {e.read().decode()[:300]}") from None
        if notify:
            return None
        if raw.lstrip().startswith("{"):
            msg = json.loads(raw)
        else:  # streamable-HTTP SSE framing
            data = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]
            msg = json.loads(data[-1])
        if "error" in msg:
            raise SystemExit(f"Polaris MCP {method}: {msg['error']}")
        return msg["result"]

    def list_tools(self):
        return self._rpc("tools/list")

    def call(self, tool: str, **args):
        if tool not in READ_ONLY_TOOLS:
            raise ValueError(f"{tool} is not on the read-only allowlist")
        return self._rpc("tools/call", {"name": tool, "arguments": args})


def export_issues(client: PolarisMCP, out: Path, **scope) -> int:
    """Save every list_issues page (raw) as page-0001.json, ... Returns issue count."""
    cursor, page, total = None, 0, 0
    while True:
        args = dict(scope, first=10, includeOccurrenceProperties=True, includeContext=True,
                    includeTriageProperties=True)
        if cursor:
            args["cursor"] = cursor
        res = client.call("list_issues", **args)
        page += 1
        (out / f"page-{page:04d}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
        data = json.loads(res["content"][0]["text"]).get("data", {})
        items = data.get("_items", [])
        total += len(items)
        cursor = items[-1].get("_cursor") if items else None
        if not items or len(items) < 10 or not cursor:
            break
    fetch_types(client, out, **scope)
    return total


def fetch_types(client: PolarisMCP, out: Path, **scope) -> int:
    """Fetch static types by weaknessId and DAST types by original issue id."""
    from fva.adapters.polaris import is_dast
    first_issue: dict[str, str] = {}
    dast_issues: list[str] = []
    for page in sorted(out.glob("page-*.json")):
        data = json.loads(json.loads(page.read_text(encoding="utf-8"))["content"][0]["text"]).get("data", {})
        for it in data.get("_items", []):
            if is_dast(it):
                if it["id"] not in dast_issues:
                    dast_issues.append(it["id"])
            else:
                first_issue.setdefault(it.get("weaknessId"), it["id"])
    types = {}
    for wid, iid in first_issue.items():
        res = client.call("get_issue", issueId=iid, includeType=True, includeOccurrenceProperties=False,
                          includeFirstDetectedOn=False, **{k: v for k, v in scope.items() if k != "branchId"})
        types[wid] = json.loads(res["content"][0]["text"]).get("data", {}).get("type")
    dast_types = {}
    for issue_id in dast_issues:
        res = client.call("get_issue", issueId=issue_id, includeType=True, includeOccurrenceProperties=False,
                          includeFirstDetectedOn=False, **{k: v for k, v in scope.items() if k != "branchId"})
        dast_types[issue_id] = json.loads(res["content"][0]["text"]).get("data", {}).get("type")
    (out / "types.json").write_text(json.dumps(types, indent=1), encoding="utf-8")
    (out / "dast-types.json").write_text(json.dumps(dast_types, indent=1), encoding="utf-8")
    return len(types) + len(dast_types)

KEYWORDS = ("dast", "tooltype", "correlat", "related", "link", "trace", "event", "endpoint", "url", "reachab")
_ERRORS = (ValueError, SystemExit, KeyError)


def _decode(res):
    try:
        return json.loads(res["content"][0]["text"])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _ids(obj) -> list[str]:
    """Best-effort: every `id` of every dict in a decoded JSON tree, in order, de-duplicated."""
    found: list[str] = []

    def walk(o):
        if isinstance(o, dict):
            if isinstance(o.get("id"), str) and o["id"] not in found:
                found.append(o["id"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(obj)
    return found


def _hash(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()[:8]


def _scrub(msg, known=()) -> str:
    """URLs, ids already seen, and anything id-shaped (UUIDs, long hex/base64 runs, e.g. a tenant id) -> placeholders."""
    msg = re.sub(r"https?://\S+", "[URL]", str(msg))
    msg = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[ID]", msg)
    msg = re.sub(r"\b[A-Za-z0-9+/_-]{24,}={0,2}", "[ID]", msg)
    for k in known:
        msg = msg.replace(k, "[ID]") if k else msg
    return msg[:200]


def _save(out: Path, name: str, res) -> None:
    (out / "raw" / name).write_text(json.dumps(res, indent=1), encoding="utf-8")


def _tool_schemas(listing) -> list[dict]:
    rows = []
    for t in (listing or {}).get("tools", []):
        sch = t.get("inputSchema") or {}
        props = sch.get("properties") or {}
        texts = [t.get("name", ""), t.get("description", "")]
        for k, v in props.items():
            texts += [k, (v or {}).get("description", "")]
        blob = " ".join(str(x) for x in texts).lower()
        rows.append({"name": t.get("name"), "arguments": list(props), "required": list(sch.get("required") or []),
                     "include_flags": [k for k, v in props.items()
                                       if k.startswith("include") and (v or {}).get("type") == "boolean"],
                     "read_only": t.get("name") in READ_ONLY_TOOLS,
                     "keyword_hits": {kw: kw in blob for kw in KEYWORDS}})
    return rows


def inventory(client, out: Path, *, project: str | None = None, branch: str | None = None, samples: int = 3,
              max_issues: int = 2000) -> dict:
    """Read-only survey of the MCP server: tool schemas, tool types per project, max-detail sample issues.

    Raw responses go to out/raw/ (real ids, local only); inventory.json/.md hold only sanitized facts."""
    out = Path(out)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    listing = client.list_tools()
    _save(out, "tools-list.json", listing)
    tools = _tool_schemas(listing)
    schema = {t["name"]: t for t in tools}
    errors: dict[str, str] = {}
    known: list[str] = []  # real ids seen, scrubbed out of error strings

    def args_for(tool, ids):
        t = schema[tool]  # KeyError when the server lacks the tool
        args = {a: ids[a] for a in t["arguments"] if ids.get(a)}
        missing = [r for r in t["required"] if r not in args]
        if missing:
            raise KeyError(f"{tool}: cannot supply required argument(s) {missing}")
        return args

    def step(label, fn):
        try:
            return fn()
        except _ERRORS as e:
            errors[label] = _scrub(f"{type(e).__name__}: {e}", known)
        return None

    projects: list[str] = [project] if project else []
    scope_ids = {"branchId": branch} if branch else {}
    n_apps = n_branches = 0
    if project is None:
        portfolio = None

        def get_portfolio():
            nonlocal portfolio
            res = client.call("get_portfolio_id")
            _save(out, "get_portfolio_id.json", res)
            d = _decode(res)
            found = _ids(d)
            data = d.get("data") if isinstance(d, dict) else None
            portfolio = found[0] if found else (data if isinstance(data, str) else None)
            known.append(portfolio or "")
        step("get_portfolio_id", get_portfolio)
        ids = {"portfolioId": portfolio}

        apps: list[str] = []

        def get_apps():
            res = client.call("get_portfolio_applications", **args_for("get_portfolio_applications", ids))
            _save(out, "get_portfolio_applications.json", res)
            apps.extend(_ids(_decode(res)))
        step("get_portfolio_applications", get_apps)
        n_apps = len(apps)
        known.extend(apps)

        def get_projects():
            t = schema["get_portfolio_projects"]
            per_app = "applicationId" in t["required"] and "applicationId" in t["arguments"]
            for i, a in enumerate(apps if per_app else [None]):
                res = client.call("get_portfolio_projects", **args_for("get_portfolio_projects", dict(ids, applicationId=a)))
                _save(out, f"get_portfolio_projects-{i + 1}.json", res)
                projects.extend(p for p in _ids(_decode(res)) if p not in projects and p not in apps and p != portfolio)
        step("get_portfolio_projects", get_projects)
        known.extend(projects)

        def get_branches(p):
            res = client.call("get_branches", **args_for("get_branches", {"projectId": p}))
            _save(out, f"get_branches-{_hash(p)}.json", res)
            return len(_ids(_decode(res)))
        for p in projects:
            n_branches += step(f"get_branches[{_hash(p)}]", lambda p=p: get_branches(p)) or 0

    def dashboard(p):
        res = client.call("get_project_dashboard", **args_for("get_project_dashboard", dict(scope_ids, projectId=p)))
        _save(out, f"get_project_dashboard-{_hash(p)}.json", res)
    known.extend(p for p in projects if p not in known)
    for p in projects:
        step(f"get_project_dashboard[{_hash(p)}]", lambda p=p: dashboard(p))

    # tool-type counts per project, remembering the first issue ids of each type
    counts: dict[str, dict[str, int]] = {}
    remembered: dict[str, list[tuple[str, str]]] = {}
    for p in projects:
        counts[_hash(p)] = c = {}

        def page_issues(p=p, c=c):
            cursor, total = None, 0
            while total < max_issues:
                args = dict(scope_ids, projectId=p, first=10, includeContext=True)
                if cursor:
                    args["cursor"] = cursor
                items = ((_decode(client.call("list_issues", **args)) or {}).get("data") or {}).get("_items", [])
                for it in items:
                    tt = str(((it.get("context") or {}).get("toolType")) or "unknown")
                    c[tt] = c.get(tt, 0) + 1
                    known.append(it.get("id") or "")
                    if len([1 for q, _ in remembered.get(tt, []) if q == p]) < samples and it.get("id"):
                        remembered.setdefault(tt, []).append((p, it["id"]))
                total += len(items)
                cursor = items[-1].get("_cursor") if items else None
                if len(items) < 10 or not cursor:
                    break
        step(f"list_issues[{_hash(p)}]", page_issues)

    # maximal-detail samples: every boolean include* flag of get_issue switched on
    flags = schema.get("get_issue", {}).get("include_flags", [])
    keys: dict[str, dict[str, set]] = {}
    for tt, entries in remembered.items():
        for n, (p, iid) in enumerate(entries, 1):
            def sample(p=p, iid=iid, tt=tt, n=n):
                res = client.call("get_issue", issueId=iid, projectId=p, **({"branchId": branch} if branch else {}),
                                  **{f: True for f in flags})
                _save(out, f"get_issue-{re.sub(r'[^A-Za-z0-9_-]', '_', tt)}-{n}.json", res)
                data = (_decode(res) or {}).get("data")
                k = keys.setdefault(tt, {"data_keys": set(), "occurrence_property_keys": set()})
                if isinstance(data, dict):
                    k["data_keys"].update(data)
                    for op in data.get("occurrenceProperties") or []:
                        if isinstance(op, dict) and "key" in op:
                            k["occurrence_property_keys"].add(str(op["key"]))
            step(f"get_issue[{tt}-{n}]", sample)

    summary = {"tools": tools,
               "discovery": {"projects": len(projects), "applications": n_apps, "branches": n_branches,
                             "errors": errors},
               "tool_type_counts": counts,
               "tool_types": sorted({tt for c in counts.values() for tt in c}),
               "sample_keys": {tt: {k: sorted(v) for k, v in d.items()} for tt, d in sorted(keys.items())}}
    (out / "inventory.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    (out / "inventory.md").write_text(_inventory_md(summary), encoding="utf-8")
    return summary


def _inventory_md(s: dict) -> str:
    L = ["# Polaris MCP inventory", "", "## Tools", "",
         "| tool | read-only | arguments | include flags | keyword hits |", "|---|---|---|---|---|"]
    for t in s["tools"]:
        hits = ", ".join(k for k, v in t["keyword_hits"].items() if v) or "-"
        L.append(f"| {t['name']} | {'yes' if t['read_only'] else 'NO'} | {', '.join(t['arguments']) or '-'} | "
                 f"{', '.join(t['include_flags']) or '-'} | {hits} |")
    d = s["discovery"]
    L += ["", "## Discovery", "", f"projects {d['projects']}, applications {d['applications']}, branches {d['branches']}", ""]
    L += [f"- {k}: {v}" for k, v in d["errors"].items()] or ["No errors."]
    L += ["", "## Issues per tool type (project = sha256(id)[:8])", "", "| project | tool type | issues |", "|---|---|---|"]
    L += [f"| {p} | {tt} | {n} |" for p, c in s["tool_type_counts"].items() for tt, n in sorted(c.items())]
    L += ["", "## Keys in maximal-detail get_issue samples", "", "| tool type | data keys | occurrence property keys |", "|---|---|---|"]
    L += [f"| {tt} | {', '.join(k['data_keys']) or '-'} | {', '.join(k['occurrence_property_keys']) or '-'} |"
          for tt, k in s["sample_keys"].items()]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m fva.polaris_mcp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample", help="save raw tools/list and get_issue responses")
    s.add_argument("--project", required=True)
    s.add_argument("--issue", action="append", required=True)
    s.add_argument("--out", default="data/polaris-samples")
    pr = sub.add_parser("probe", help="save extended SCA responses (component locations, reachability)")
    pr.add_argument("--project", required=True)
    pr.add_argument("--branch")
    pr.add_argument("--issue", action="append", required=True)
    pr.add_argument("--component", action="append", default=[], help="component name to look up")
    pr.add_argument("--out", default="data/polaris-samples")
    ex = sub.add_parser("export", help="page through list_issues and save raw pages")
    ex.add_argument("--project", required=True)
    ex.add_argument("--branch")
    ex.add_argument("--out", default="data/polaris-export")
    ex.add_argument("--types-only", action="store_true", help="only (re)fetch types.json for an existing export")
    iv = sub.add_parser("inventory", help="read-only survey: tool schemas, tool types, max-detail sample issues")
    iv.add_argument("--project")
    iv.add_argument("--branch")
    iv.add_argument("--samples", type=int, default=3, help="sample issues per tool type per project")
    iv.add_argument("--max-issues", type=int, default=2000)
    iv.add_argument("--out", default="data/polaris-inventory")
    a = ap.parse_args(argv)
    if a.cmd == "inventory":
        out = Path(a.out)
        summ = inventory(PolarisMCP(), out, project=a.project, branch=a.branch, samples=a.samples,
                         max_issues=a.max_issues)
        n = sum(sum(c.values()) for c in summ["tool_type_counts"].values())
        print(f"{len(summ['tools'])} tools, {summ['discovery']['projects']} projects, {n} issues "
              f"({', '.join(summ['tool_types']) or 'none'}) -> {out / 'inventory.json'}")
        return
    if a.cmd == "export":
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        scope = {"projectId": a.project, **({"branchId": a.branch} if a.branch else {})}
        if a.types_only:
            print(f"saved {fetch_types(PolarisMCP(), out, **scope)} issue types -> {out / 'types.json'}")
            return
        n = export_issues(PolarisMCP(), out, **scope)
        print(f"saved {n} issues -> {out}")
        return
    if a.cmd == "probe":
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        c = PolarisMCP()
        scope = {"projectId": a.project, **({"branchId": a.branch} if a.branch else {})}
        for iid in a.issue:
            res = c.call("get_issue", issueId=iid, **scope, includeComponentLocations=True, includeContext=True,
                         includeTriageProperties=True, includeExtensionProperties=True)
            (out / f"get_issue-full-{iid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
            print(f"saved get_issue-full-{iid}.json")
        for name in a.component:
            res = c.call("list_component_versions", **scope, filter=f"component:name=isubstr='{name}'",
                         includeComponent=True, includeContext=True)
            safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)
            (out / f"list_component_versions-{safe}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
            print(f"saved list_component_versions-{safe}.json")
        return
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    c = PolarisMCP()
    (out / "tools-list.json").write_text(json.dumps(c.list_tools(), indent=1), encoding="utf-8")
    for iid in a.issue:
        res = c.call("get_issue", issueId=iid, projectId=a.project)
        (out / f"get_issue-{iid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
        print(f"saved get_issue-{iid}.json")
    print(f"saved tools-list.json -> {out}")


if __name__ == "__main__":
    main()
