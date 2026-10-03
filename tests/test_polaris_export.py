import json

from fva.polaris_mcp import fetch_types


def _response(data):
    return {"content": [{"text": json.dumps({"data": data})}]}


class StubClient:
    def __init__(self, types_by_issue):
        self.types_by_issue = types_by_issue
        self.calls = []

    def call(self, tool, **args):
        assert tool == "get_issue"
        self.calls.append(args)
        return _response({"type": self.types_by_issue[args["issueId"]]})


def test_export_keeps_static_weakness_dedup_and_dast_issue_identity(tmp_path):
    issues = [
        {"id": "static-1", "weaknessId": "shared-weakness", "context": {"toolType": "sast"}},
        {"id": "static-2", "weaknessId": "shared-weakness", "context": {"toolType": "SCA"}},
        {"id": "dast-1", "weaknessId": "shared-weakness", "context": {"toolType": "DAST"}},
        {"id": "dast-2", "weaknessId": "shared-weakness", "context": {"toolType": "dast"}},
    ]
    page = {"content": [{"text": json.dumps({"data": {"_items": issues}})}]}
    (tmp_path / "page-0001.json").write_text(json.dumps(page), encoding="utf-8")
    client = StubClient({
        "static-1": {"name": "Static weakness type"},
        "dast-1": {"name": "DAST issue one"},
        "dast-2": {"name": "DAST issue two"},
    })

    assert fetch_types(client, tmp_path, projectId="synthetic-project", branchId="synthetic-branch") == 3

    assert json.loads((tmp_path / "types.json").read_text(encoding="utf-8")) == {
        "shared-weakness": {"name": "Static weakness type"}
    }
    assert json.loads((tmp_path / "dast-types.json").read_text(encoding="utf-8")) == {
        "dast-1": {"name": "DAST issue one"},
        "dast-2": {"name": "DAST issue two"},
    }
    assert [call["issueId"] for call in client.calls] == ["static-1", "dast-1", "dast-2"]
    assert all(call["includeType"] is True for call in client.calls)
    assert all(call["projectId"] == "synthetic-project" and "branchId" not in call for call in client.calls)
