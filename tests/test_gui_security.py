"""Security tests for GUI subprocess allowlisting."""

import sys

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_demo_allowlist_contains_known_modes():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("python -c 'print(1)'")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command payload" in output


def test_run_command_rejects_non_main_executable():
    status, output = _run_command([sys.executable, "-c", "print(1)"])
    assert status == "Error"
    assert "allowlisted" in output
