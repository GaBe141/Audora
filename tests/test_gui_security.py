"""Security tests for GUI subprocess allowlisting."""

import sys
from pathlib import Path

from gui.app import ALLOWED_DEMO_MODES, _is_allowlisted_command, _run_command


def test_allowed_demo_modes_match_cli_choices():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_main_payload():
    status, output = _run_command([sys.executable, "-c", "print('nope')"])
    assert status == "Error"
    assert "not allowlisted" in output


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("echo pwned")  # type: ignore[arg-type]
    assert status == "Error"
    assert "not allowlisted" in output


def test_is_allowlisted_command_accepts_current_interpreter_and_main():
    main_py = str(Path(__file__).resolve().parents[1] / "main.py")
    assert _is_allowlisted_command([sys.executable, main_py, "--demo", "statistical"]) is True
    assert _is_allowlisted_command(["/bin/sh", main_py]) is False
    assert _is_allowlisted_command([sys.executable]) is False
