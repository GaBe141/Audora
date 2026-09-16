"""Security tests for GUI command and webhook handling."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _run_command, _validated_demo_mode


class TestGuiCommandGuards:
    """GUI subprocess helpers must reject untrusted payloads."""

    def test_demo_allowlist_matches_cli_choices(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_validated_demo_mode_rejects_unknown_values(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validated_demo_mode("--help; cat /etc/passwd")

    def test_validated_demo_mode_accepts_allowlisted_value(self):
        assert _validated_demo_mode("statistical") == "statistical"

    def test_run_command_rejects_non_list_payload(self):
        status, output = _run_command("rm -rf /")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command(["python", 123])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command payload" in output
