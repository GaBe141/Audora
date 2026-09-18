"""Security tests for GUI command construction."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _demo_command, _validate_command_args


class TestGuiCommandHardening:
    """GUI subprocess helpers must reject attacker-controlled arguments."""

    def test_demo_allowlist_contains_sidebar_options(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_validate_command_args_rejects_non_strings(self):
        with pytest.raises(ValueError, match="non-empty strings"):
            _validate_command_args(["python", 1])  # type: ignore[list-item]

    def test_validate_command_args_rejects_empty_list(self):
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_command_args([])

    def test_validate_command_args_rejects_nul(self):
        with pytest.raises(ValueError, match="non-empty strings"):
            _validate_command_args(["python", "main.py\x00--demo"])

    def test_demo_command_rejects_unknown_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _demo_command("statistical; rm -rf /")

    def test_demo_command_builds_allowlisted_argv(self):
        args = _demo_command("statistical")
        assert args[-2:] == ["--demo", "statistical"]
        assert all(isinstance(arg, str) for arg in args)
