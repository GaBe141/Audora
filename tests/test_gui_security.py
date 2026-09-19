"""Security tests for GUI subprocess and webhook configuration."""

import pytest

pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, _validate_command_args  # noqa: E402


class TestGuiCommandHardening:
    """GUI must not pass attacker-controlled argv to subprocess."""

    def test_allowlisted_demo_modes_match_cli(self):
        expected = frozenset({"statistical", "trending", "multi_source", "platform", "all"})
        assert expected == ALLOWED_DEMO_MODES

    def test_rejects_non_string_args(self):
        with pytest.raises(ValueError, match="strings"):
            _validate_command_args([1, "ok"])  # type: ignore[list-item]

    def test_rejects_nul_bytes(self):
        with pytest.raises(ValueError, match="NUL"):
            _validate_command_args(["python", "main.py\x00--demo"])

    def test_rejects_empty_command(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_command_args([])
