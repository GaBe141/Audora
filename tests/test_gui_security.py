"""Security tests for GUI command construction and webhook persistence."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    _validate_command_args,
    _validate_demo_mode,
)


class TestGuiCommandValidation:
    """GUI subprocess helpers must reject unexpected payloads."""

    def test_demo_allowlist_matches_main_parser(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_rejects_unknown_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validate_demo_mode("; rm -rf /")

    def test_rejects_non_string_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            _validate_demo_mode(None)

    def test_accepts_known_demo_mode(self):
        assert _validate_demo_mode("statistical") == "statistical"

    def test_rejects_nul_in_command_args(self):
        with pytest.raises(ValueError, match="Invalid command arguments"):
            _validate_command_args(["python", "main.py\x00--demo"])

    def test_rejects_non_string_command_args(self):
        with pytest.raises(ValueError, match="Invalid command arguments"):
            _validate_command_args(["python", 123])  # type: ignore[list-item]
