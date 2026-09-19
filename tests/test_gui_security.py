"""Security tests for GUI subprocess and webhook settings."""

from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, _run_command, run_action, save_settings


def test_allowed_demo_modes_match_cli_choices():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command(["python", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "list of strings" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["python", "evil\x00arg"])
    assert status == "Error"
    assert "NUL" in output


def test_run_action_rejects_unknown_demo_mode():
    with patch("gui.app.ctx") as mock_ctx:
        mock_ctx.triggered_id = "btn-demo"
        status, output = run_action(1, 1, 0, 0, "not-a-real-demo; rm -rf /")
    assert status == "Error"
    assert output == "Invalid demo mode"


def test_save_settings_validates_webhook_urls():
    result = save_settings(1, "http://evil.example/slack", None, None, None, None, None, None)
    assert result.startswith("Error:")
    assert "HTTPS" in result
