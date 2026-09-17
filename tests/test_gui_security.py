"""Security tests for GUI command execution and webhook settings."""

import sys

from gui.app import ALLOWED_DEMO_MODES, _run_command, save_settings


def test_allowed_demo_modes_match_cli_choices():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("rm -rf /")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command payload" in output


def test_run_command_rejects_foreign_interpreter():
    status, output = _run_command(["/bin/sh", "main.py"])
    assert status == "Error"
    assert "interpreter" in output


def test_run_command_rejects_non_main_target(tmp_path):
    status, output = _run_command([sys.executable, str(tmp_path / "evil.py")])
    assert status == "Error"
    assert "target" in output


def test_save_settings_rejects_http_webhook():
    result = save_settings(
        1,
        "http://evil.example/slack",
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert result.startswith("Error:")
    assert "HTTPS" in result
