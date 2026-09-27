"""Minimal read-only client for the Polaris Issue Management MCP server.

Credentials come from the environment (never from code or committed config):
  POLARIS_URL            e.g. https://poc.polaris.blackduck.com   (default)
  POLARIS_ACCESS_TOKEN   Polaris access token
Falls back to data/.polaris-token (git-ignored) if the variable is unset.

Capture raw sample responses (for adapter fixtures):
  python -m fva.polaris_mcp sample --project <projectId> --issue <sastIssueId> --issue <scaIssueId>
Writes data/polaris-samples/*.json. The token is never printed or saved.
"""
from __future__ import annotations

import argparse
import json
import os
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
    a = ap.parse_args(argv)
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
