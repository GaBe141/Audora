"""Security tests for GUI subprocess and webhook input validation."""

import pytest

dash = pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, _validate_command_args  # noqa: E402


class TestGuiCommandValidation:
    """GUI subprocess helpers must reject attacker-controlled argv."""

    def test_allowed_demo_modes_match_cli_choices(self):
        expected = frozenset({"statistical", "trending", "multi_source", "platform", "all"})
        assert expected == ALLOWED_DEMO_MODES

    def test_rejects_non_string_and_nul_arguments(self):
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_command_args("python")
        with pytest.raises(ValueError, match="NUL"):
            _validate_command_args(["python", "main.py\x00--demo"])
        with pytest.raises(ValueError, match="strings"):
            _validate_command_args(["python", 1])

    def test_accepts_explicit_string_argv(self):
        args = ["python", "main.py", "--demo", "statistical"]
        assert _validate_command_args(args) == args
