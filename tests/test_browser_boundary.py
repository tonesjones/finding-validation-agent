"""Node policy/transport checks; real browser coverage is opt-in and local only."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_browser_boundary():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Optional browser boundary requires Node")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("browser_boundary.cjs"))],
        capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
