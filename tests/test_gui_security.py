"""Security tests for GUI command allowlisting."""

import sys
from pathlib import Path

from gui.app import _ALLOWED_DEMO_MODES, PROJECT_ROOT, _run_command


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("rm -rf /")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_non_allowlisted_binary():
    status, output = _run_command(["/bin/echo", "pwned"])
    assert status == "Error"
    assert "allowlisted" in output


def test_run_command_rejects_unexpected_script(tmp_path):
    status, output = _run_command([sys.executable, str(tmp_path / "evil.py")])
    assert status == "Error"
    assert "allowlisted" in output


def test_run_command_rejects_unexpected_flag():
    status, output = _run_command(
        [sys.executable, str(PROJECT_ROOT / "main.py"), "--extra", "steal"]
    )
    assert status == "Error"
    assert "allowlisted" in output


def test_demo_modes_are_strictly_allowlisted():
    assert "statistical" in _ALLOWED_DEMO_MODES
    assert "../evil" not in _ALLOWED_DEMO_MODES
    assert Path(__file__).name not in _ALLOWED_DEMO_MODES
