"""Security tests for GUI subprocess and webhook configuration."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    _run_command,
    _validated_demo_mode,
    save_settings,
)


class TestGuiDemoAllowlist:
    def test_allowed_demo_modes_match_cli(self):
        expected = {"statistical", "trending", "multi_source", "platform", "all"}
        assert expected == ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command(["python", 1])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_nul_bytes(self):
        status, output = _run_command(["python", "main.py\x00--evil"])
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_validated_demo_mode_rejects_unknown_value(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validated_demo_mode("; rm -rf /")

    def test_validated_demo_mode_rejects_non_string(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validated_demo_mode(["statistical", "--setup"])

    def test_validated_demo_mode_accepts_allowlisted_value(self):
        assert _validated_demo_mode("statistical") == "statistical"


class TestGuiWebhookSaveValidation:
    def test_save_settings_rejects_http_webhook(self):
        result = save_settings(
            1,
            "http://hooks.example.com/slack",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert result.startswith("Error:")
        assert "HTTPS" in result
