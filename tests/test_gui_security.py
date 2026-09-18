"""Security tests for GUI demo-mode allowlisting and subprocess argv validation."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _run_command, _validate_command_args


class TestGuiCommandValidation:
    def test_allowed_demo_modes_match_cli(self):
        assert frozenset(
            {"statistical", "trending", "multi_source", "platform", "all"}
        ) == ALLOWED_DEMO_MODES

    def test_rejects_non_string_args(self):
        with pytest.raises(ValueError, match="strings without NUL"):
            _validate_command_args(["python", 1])  # type: ignore[list-item]

    def test_rejects_nul_bytes(self):
        with pytest.raises(ValueError, match="NUL"):
            _validate_command_args(["python", "main.py\x00--demo"])

    def test_rejects_empty_args(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_command_args([])

    def test_run_command_rejects_malformed_payload(self):
        status, output = _run_command(["python", None])  # type: ignore[list-item]
        assert status == "Error"
        assert "NUL" in output or "strings" in output
