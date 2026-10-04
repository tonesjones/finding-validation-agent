import json
from pathlib import Path

from fva.polaris_mcp import READ_ONLY_TOOLS, inventory

ISSUES = [("ISSUE-AAA-1", "sast"), ("ISSUE-AAA-2", "sast"), ("ISSUE-BBB-3", "sca"), ("ISSUE-CCC-4", "sca"),
          ("ISSUE-DDD-5", "sast")]
_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "polaris_triage_fields.json").read_text(encoding="utf-8"))
TRIAGE = {i["id"]: {k: v for k, v in i.items() if k not in ("id", "context")} for i in _FIXTURE["data"]["_items"]}
SECRETS = ["Secret Project Name", "tenant.internal", "TENANT-123", "PROJ-SECRET-ID"] + [i for i, _ in ISSUES]
SECRETS += ["synthetic-user", "2099-01"]


def _tool(name, props=None, required=(), desc=""):
    return {"name": name, "description": desc, "inputSchema": {
        "properties": {k: {"type": t} for k, t in (props or {}).items()}, "required": list(required)}}


def _env(data):
    return {"content": [{"type": "text", "text": json.dumps({"data": data})}]}


class StubClient:
    def __init__(self):
        self.calls = []

    def list_tools(self):
        return {"tools": [
            _tool("get_issue", {"issueId": "string", "projectId": "string", "includeType": "boolean",
                                "includeComponentLocations": "boolean", "includeContext": "boolean", "limit": "integer"},
                  ["issueId"], "Get one issue with its toolType"),
            _tool("list_issues", {"projectId": "string", "first": "integer", "cursor": "string"}),
            _tool("get_portfolio_id"),
            _tool("get_portfolio_applications", {"portfolioId": "string"}, ["portfolioId"]),
            _tool("get_portfolio_projects", {"portfolioId": "string"}, ["portfolioId"]),
            _tool("get_branches", {"projectId": "string"}, ["projectId"]),
            _tool("get_project_dashboard", {"projectId": "string"}, ["projectId"], "DAST endpoint summary"),
        ]}

    def call(self, tool, **args):
        if tool not in READ_ONLY_TOOLS:
            raise ValueError(f"{tool} is not on the read-only allowlist")
        self.calls.append((tool, args))
        if tool == "get_portfolio_id":
            return _env({"id": "PORT-1", "tenantId": "TENANT-123"})
        if tool == "get_portfolio_applications":
            assert args == {"portfolioId": "PORT-1"}
            return _env({"_items": [{"id": "APP-1", "name": "Secret Project Name"}]})
        if tool == "get_portfolio_projects":
            assert args == {"portfolioId": "PORT-1"}
            return _env({"_items": [{"id": "PROJ-SECRET-ID", "name": "Secret Project Name",
                                     "_links": {"self": "https://tenant.internal/api/x"}}]})
        if tool == "get_branches":
            assert args == {"projectId": "PROJ-SECRET-ID"}
            return _env({"_items": [{"id": "BR-1", "name": "Secret Project Name"}]})
        if tool == "get_project_dashboard":
            return _env({"url": "https://tenant.internal/api/x"})
        if tool == "list_issues":
            assert args["includeContext"] is True and args["includeTriageProperties"] is True and args["first"] == 10
            start = int(args["cursor"]) if args.get("cursor") else 0
            page = ISSUES[start:start + 10]
            return _env({"_items": [{**TRIAGE[i], "id": i, "weaknessId": "w", "_cursor": str(start + n + 1),
                                     "context": {"toolType": t}} for n, (i, t) in enumerate(page)]})
        if tool == "get_issue":
            tt = dict(ISSUES)[args["issueId"]]
            extra = {"occurrenceProperties": [{"key": "file", "value": "Secret Project Name"}]} if tt == "sast" else {}
            return _env({"id": args["issueId"], "type": "t", "context": {"toolType": tt}, **extra})
        raise AssertionError(tool)


def _run(tmp_path, **kw):
    c = StubClient()
    return c, inventory(c, tmp_path, **kw)


def _no_secrets(tmp_path):
    for name in ("inventory.json", "inventory.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        for s in SECRETS:
            assert s not in text, (name, s)


def test_discovery_counts_and_flags(tmp_path):
    c, s = _run(tmp_path, samples=2)
    assert all(t in READ_ONLY_TOOLS for t, _ in c.calls)
    gi = [a for t, a in c.calls if t == "get_issue"]
    assert gi and all(a["projectId"] == "PROJ-SECRET-ID" for a in gi)
    for a in gi:
        assert {k for k, v in a.items() if v is True} == {"includeType", "includeComponentLocations", "includeContext"}
        assert "limit" not in a
    assert len(gi) == 4  # 2 samples per tool type
    (counts,) = s["tool_type_counts"].values()
    assert counts == {"sast": 3, "sca": 2}
    assert s["discovery"] == {"projects": 1, "applications": 1, "branches": 1, "errors": {}}
    assert s["sample_keys"]["sast"]["occurrence_property_keys"] == ["file"]
    assert "occurrenceProperties" in s["sample_keys"]["sast"]["data_keys"]
    assert "occurrenceProperties" not in s["sample_keys"]["sca"]["data_keys"]
    gi_tool = next(t for t in s["tools"] if t["name"] == "get_issue")
    assert gi_tool["include_flags"] == ["includeType", "includeComponentLocations", "includeContext"]
    assert gi_tool["keyword_hits"]["tooltype"] and not gi_tool["keyword_hits"]["dast"]
    assert next(t for t in s["tools"] if t["name"] == "get_project_dashboard")["keyword_hits"]["dast"]
    raw = {p.name for p in (tmp_path / "raw").iterdir()}
    assert {"tools-list.json", "get_issue-sast-1.json", "get_issue-sca-2.json"} <= raw
    assert not any("ISSUE" in n or "PROJ-SECRET" in n for n in raw)
    _no_secrets(tmp_path)


def test_triage_fields_from_list_pages(tmp_path):
    c, s = _run(tmp_path, samples=1)
    assert {t for t, _ in c.calls} <= READ_ONLY_TOOLS
    assert s["triage_fields"] == {"issues_examined": 5, "fields": {
        "triage status": {"presence": "present", "issues": 4},
        "set-by": {"presence": "present", "issues": 2},
        "set-at": {"presence": "present", "issues": 2},
        "status history": {"presence": "present", "issues": 2}}}
    assert sum(t == "get_issue" for t, _ in c.calls) == 2  # still samples only
    assert "| set-by | present | 2 |" in (tmp_path / "inventory.md").read_text(encoding="utf-8")
    _no_secrets(tmp_path)


def test_project_given_skips_portfolio_discovery(tmp_path):
    c, s = _run(tmp_path, project="PROJ-SECRET-ID", samples=1)
    called = {t for t, _ in c.calls}
    assert not called & {"get_portfolio_id", "get_portfolio_applications", "get_portfolio_projects", "get_branches"}
    assert "list_issues" in called and "get_issue" in called
    (counts,) = s["tool_type_counts"].values()
    assert counts == {"sast": 3, "sca": 2}
    _no_secrets(tmp_path)


def test_max_issues_and_discovery_errors_are_scrubbed(tmp_path):
    class Failing(StubClient):
        def call(self, tool, **args):
            if tool == "get_portfolio_applications":
                raise SystemExit("HTTP 500 https://tenant.internal/api/x PORT-1 failed")
            return super().call(tool, **args)
    c = Failing()
    s = inventory(c, tmp_path, max_issues=1)
    err = s["discovery"]["errors"]["get_portfolio_applications"]
    assert "[URL]" in err and "tenant.internal" not in err and "PORT-1" not in err and len(err) <= 200
    (counts,) = s["tool_type_counts"].values()
    assert sum(counts.values()) == 5  # page granularity: first page of 10 already fetched
    _no_secrets(tmp_path)
