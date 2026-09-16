"""Security tests for GUI subprocess orchestration."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_allowed_demo_modes_match_cli_choices():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_list_payloads():
    status, output = _run_command("rm -rf /")  # type: ignore[arg-type]
    assert status == "Error"
    assert output == "Invalid command arguments"


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command(["python", 123])  # type: ignore[list-item]
    assert status == "Error"
    assert output == "Invalid command arguments"
