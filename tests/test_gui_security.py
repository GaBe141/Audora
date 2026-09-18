"""Security tests for GUI command orchestration."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command(["python", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_empty_argument_list():
    status, output = _run_command([])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_demo_modes_are_allowlisted():
    assert ALLOWED_DEMO_MODES == frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    )
    assert "../evil" not in ALLOWED_DEMO_MODES
    assert "; rm -rf /" not in ALLOWED_DEMO_MODES
