import json
import os
import shlex
import subprocess
import sys

import pytest

from fva.correlation.source_pin import pin
from fva.redact import redact, redact_http, redact_value
from fva.reasoning.model import CodexCliClient


@pytest.mark.parametrize("helper", ["clean", "process"])
def test_source_pin_never_enters_submodules(tmp_path, helper):
    parent = tmp_path / "parent"
    origin = tmp_path / "origin"
    parent.mkdir()
    origin.mkdir()

    def git(root, *args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    def commit(root):
        git(root, "add", ".")
        git(root, "-c", "user.email=test@example.invalid", "-c", "user.name=Test",
            "commit", "-qm", "fixture")

    git(origin, "init", "-q")
    (origin / ".gitattributes").write_text("*.txt filter=child.only\n")
    (origin / "file.txt").write_text("original\n")
    commit(origin)
    git(parent, "init", "-q")
    (parent / "app.js").write_text("export const value = 1;\n")
    git(parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
        origin.as_posix(), "sub")
    commit(parent)
    child = parent / "sub"
    git(parent, "config", "diff.ignoreSubmodules", "none")
    git(parent, "config", "submodule.sub.ignore", "none")
    git(parent, "config", "diff.submodule", "diff")
    marker = tmp_path / "CALLBACK-RAN"
    callback = tmp_path / "callback.py"
    callback.write_text("import sys\nfrom pathlib import Path\n"
                        f"Path({str(marker)!r}).write_text('ran')\n"
                        + ("sys.stdout.write(sys.stdin.read())\n" if helper == "clean" else ""))
    command = f'{shlex.quote(sys.executable.replace(chr(92), "/"))} {shlex.quote(callback.as_posix())}'
    git(child, "config", f"filter.child.only.{helper}", command)
    changed = child / "file.txt"
    changed.write_text("modified\n")
    os.utime(changed, ns=(changed.stat().st_atime_ns, changed.stat().st_mtime_ns + 2_000_000_000))
    # Show that the unsafe parent diff really reaches the child-only helper.
    subprocess.run(["git", "-c", "core.fsmonitor=", "--no-optional-locks", "-C", str(parent),
                    "diff", "--no-ext-diff", "--no-textconv", "--stat", "HEAD"],
                   capture_output=True, timeout=10)
    assert marker.exists()
    marker.unlink()
    metadata = [parent / ".git/config", parent / ".git/index",
                parent / ".git/modules/sub/config", parent / ".git/modules/sub/index"]
    before = {path: path.read_bytes() for path in metadata}
    assert pin(parent).vcs_dirty is False
    assert not marker.exists()
    (parent / "app.js").write_text("export const value = 2;\n")
    assert pin(parent).vcs_dirty is True
    assert not marker.exists()
    assert all(path.read_bytes() == contents for path, contents in before.items())
    assert all(not path.with_name("index.lock").exists() for path in metadata)


@pytest.mark.parametrize("helper", ["fsmonitor", "external", "textconv", "clean", "process"])
def test_source_pin_never_executes_configured_helpers(tmp_path, helper):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "app.js").write_text("export const value = 1;\n")
    (tmp_path / ".gitattributes").write_text("*.js diff=pilot filter=pilot.driver\n")
    git("add", ".")
    git("-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-qm", "initial")
    callback = tmp_path / "callback.py"
    callback.write_text("from pathlib import Path\nPath('CALLBACK-RAN').write_text('ran')\n")
    command = f'{shlex.quote(sys.executable.replace(chr(92), "/"))} {shlex.quote(callback.as_posix())}'
    keys = {"fsmonitor": "core.fsmonitor", "external": "diff.external",
            "textconv": "diff.pilot.textconv", "clean": "filter.pilot.driver.clean",
            "process": "filter.pilot.driver.process"}
    if helper == "clean":
        included = tmp_path / ".git/filters.conf"
        included.write_text(f'[filter "pilot.driver"]\nclean = {json.dumps(command)}\nrequired = true\n')
        git("config", "include.path", str(included))
    else:
        git("config", keys[helper], command)
    if helper == "fsmonitor":
        # Reproduce the original pin invocation against this disposable checkout.
        subprocess.run(["git", "--no-optional-locks", "-C", str(tmp_path),
                        "diff", "--ignore-cr-at-eol", "--stat", "HEAD"],
                       capture_output=True, timeout=10)
        assert (tmp_path / "CALLBACK-RAN").exists()
        (tmp_path / "CALLBACK-RAN").unlink()
    before_config = (tmp_path / ".git/config").read_bytes()
    before_index = (tmp_path / ".git/index").read_bytes()
    assert pin(tmp_path).vcs_dirty is False
    (tmp_path / "app.js").write_text("export const value = 2;\n")
    assert pin(tmp_path).vcs_dirty is True
    assert not (tmp_path / "CALLBACK-RAN").exists()
    assert (tmp_path / ".git/config").read_bytes() == before_config
    assert (tmp_path / ".git/index").read_bytes() == before_index
    assert not (tmp_path / ".git/index.lock").exists()


def test_source_redaction_preserves_dynamic_auth_syntax():
    source = "headers: {\n  Authorization: `Bearer ${token}`,\n},\nauthorization: string;\n"
    assert redact(source) == source
    assert redact("authorization: if (allowed) grant();") == "authorization: if (allowed) grant();"
    assert "literal-secret" not in redact('const token = "literal-secret";')
    assert "literal-secret" not in redact('const password = `literal-secret${suffix}`;')
    assert "literal-secret" not in redact('Authorization: `Bearer ${"literal-secret"}`')
    assert "literal-secret" not in redact('const token = `${"literal-secret"}`;')
    assert "12345678" not in redact('const password = `${12345678}`;')


def test_evidence_header_redaction_removes_values_and_preserves_lines():
    request = "GET / HTTP/1.1\nAuthorization: custom-secret\nCF-Access-Client-ID: client-secret\n\n"
    masked = "GET / HTTP/1.1\nAuthorization: [REDACTED]\nCF-Access-Client-ID: [REDACTED]\n\n"
    assert redact_http(request) == masked
    assert redact_value({"evidence": [request]}) == {"evidence": [masked]}


@pytest.mark.parametrize("command", [
    "codex exec --json -", "codex --profile pilot exec --json -",
    "codex exec --ignore-user-config -", "codex exec --json --ignore-user-config -",
])
def test_audited_custom_cli_always_ignores_config(command, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: name)
    client = CodexCliClient(command=command, audit=True)
    argv = client._argv
    assert argv.count("--json") == argv.count("--ignore-user-config") == 1
    assert argv.index("--ignore-user-config") > argv.index("exec")


def test_cli_prompt_text_cannot_satisfy_isolation_flags(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: name)
    client = CodexCliClient(command="codex exec -- --json --ignore-user-config", audit=True, model="gpt-6-sol")
    options = client._argv[:client._argv.index("--")]
    assert options.count("--json") == options.count("--ignore-user-config") == 1
    assert options[options.index("-m") + 1] == "gpt-6-sol"


def test_mixed_export_round_trip_keeps_dast_types_separate(tmp_path):
    from fva.adapters import polaris
    from fva.polaris_mcp import export_issues
    from pathlib import Path
    fixture = Path(__file__).parent / "fixtures/polaris_dast_observed.json"
    issues = json.loads(fixture.read_text())["_items"]
    types = {i["id"]: i.pop("type") for i in issues}

    class Client:
        def call(self, tool, **args):
            data = {"_items": issues} if tool == "list_issues" else {"type": types[args["issueId"]]}
            return {"content": [{"type": "text", "text": json.dumps({"data": data})}]}

    assert export_issues(Client(), tmp_path) == 2
    _, findings = polaris.load_mcp(tmp_path / "page-0001.json")
    assert [f.title for f in findings] == ["Server Error", "Deprecated TLS Protocol Version"]
    assert all("type_details_missing" not in f.scanner_metadata for f in findings)
    assert json.loads((tmp_path / "types.json").read_text()) == {}


def test_discovery_cwe_normalization():
    from fva.discovery import Candidate
    row = {"title": "example", "rationale": "example", "cwe": ["79", "cwe-079", "CWE-89"],
           "severity": "low", "citations": [{"path": "app.js", "line": 1, "quote": "code"}],
           "uncertainty": "pending validation"}
    assert Candidate.model_validate(row).cwe == ["CWE-79", "CWE-89"]
    with pytest.raises(ValueError, match="CWE must"):
        Candidate.model_validate({**row, "cwe": ["CWE-79-extra"]})


@pytest.mark.parametrize("marker", ["// planted issue", "const x = 1; // VULN", "/* answer key */"])
def test_source_freezing_refuses_obvious_plant_comments(tmp_path, marker):
    from fva.discovery import freeze_source
    from fva.schemas import DeploymentProfile
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.js").write_text(marker + "\n")
    profile = DeploymentProfile(profile_id="test", name="test", language_packs=("node",))
    with pytest.raises(ValueError, match="possible plant hint"):
        freeze_source(source, profile, tmp_path / "out")
