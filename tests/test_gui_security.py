"""Security tests for GUI command execution."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _run_command, _validated_demo_mode


class TestGuiCommandSecurity:
    """GUI subprocess helpers must reject unexpected payloads."""

    def test_allowed_demo_modes_match_cli_choices(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command([123, "rm", "-rf", "/"])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_empty_args(self):
        status, output = _run_command([])
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_validated_demo_mode_rejects_unknown(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validated_demo_mode("not-a-real-demo; rm -rf /")

    def test_validated_demo_mode_accepts_allowlisted_value(self):
        assert _validated_demo_mode("statistical") == "statistical"
