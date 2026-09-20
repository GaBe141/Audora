"""Security tests for GUI subprocess and export helpers."""

import pytest

from gui.app import _ALLOWED_DEMO_MODES, _build_demo_command, _sanitize_command_args


class TestGuiCommandHardening:
    """Sidebar actions must not accept attacker-controlled argv."""

    def test_allowlisted_demo_builds_command(self):
        args = _build_demo_command("statistical")
        assert args[-2:] == ["--demo", "statistical"]
        assert set(_ALLOWED_DEMO_MODES) == {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        }

    def test_rejects_unknown_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _build_demo_command("statistical; rm -rf /")

    def test_rejects_non_string_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _build_demo_command(["statistical"])

    def test_rejects_nul_in_command_args(self):
        with pytest.raises(ValueError, match="Invalid command argument"):
            _sanitize_command_args(["python", "main.py\x00--demo"])
