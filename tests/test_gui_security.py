"""Security tests for GUI command construction."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_allowed_demo_modes_match_cli_choices():
    assert frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    ) == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command(["python", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert output == "Invalid command arguments"


def test_run_command_rejects_empty_argument_list():
    status, output = _run_command([])
    assert status == "Error"
    assert output == "Invalid command arguments"
