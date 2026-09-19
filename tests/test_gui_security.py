"""Security tests for the Dash prototyping GUI command and webhook paths."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_demo_modes_are_strictly_allowlisted():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command(["python", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["python", "evil\x00--flag"])
    assert status == "Error"
    assert "Invalid command arguments" in output
