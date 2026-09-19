"""Security tests for GUI subprocess and webhook input validation."""

import pytest

from gui.app import validate_demo_mode, validate_subprocess_args


class TestGuiSubprocessGuards:
    def test_accepts_allowlisted_demo_mode(self):
        assert validate_demo_mode("statistical") == "statistical"

    def test_rejects_unknown_demo_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            validate_demo_mode("--help; rm -rf /")

    def test_rejects_non_string_args(self):
        with pytest.raises(ValueError, match="non-empty list"):
            validate_subprocess_args("python main.py")  # type: ignore[arg-type]

    def test_rejects_nul_in_args(self):
        with pytest.raises(ValueError, match="Invalid command argument"):
            validate_subprocess_args(["python", "main.py\x00--demo"])
