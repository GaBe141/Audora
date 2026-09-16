"""Security tests for GUI command execution and webhook configuration."""

from pathlib import Path

import pytest

from gui.app import ALLOWED_DEMO_MODES, _run_command, _validate_demo_mode


class TestGuiDemoAllowlist:
    """Demo subprocess arguments must be restricted to known modes."""

    def test_known_modes_are_accepted(self):
        for mode in ALLOWED_DEMO_MODES:
            assert _validate_demo_mode(mode) == mode

    def test_rejects_unknown_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validate_demo_mode("all; rm -rf /")


class TestGuiCommandGuard:
    """GUI helpers must refuse non-argv command payloads."""

    def test_run_command_rejects_string_payload(self):
        status, output = _run_command("echo pwned")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command([123, "main.py"])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output


class TestLintScriptHardening:
    """Maintenance scripts must not invoke a shell."""

    def test_fix_linting_issues_does_not_use_shell(self):
        source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
        assert "shell=True" not in source
        assert "sys.executable" in source
