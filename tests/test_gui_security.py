"""Security tests for GUI command construction and demo allowlisting."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _sanitize_cli_arg


class TestDemoAllowlist:
    def test_known_demo_modes_are_listed(self):
        assert "statistical" in ALLOWED_DEMO_MODES
        assert "all" in ALLOWED_DEMO_MODES

    def test_arbitrary_demo_mode_is_rejected(self):
        assert "--help" not in ALLOWED_DEMO_MODES
        assert "; rm -rf /" not in ALLOWED_DEMO_MODES


class TestSanitizeCliArg:
    def test_accepts_plain_string(self):
        assert _sanitize_cli_arg("--demo") == "--demo"

    def test_rejects_non_string(self):
        with pytest.raises(ValueError, match="strings"):
            _sanitize_cli_arg(["--demo", "all"])

    def test_rejects_nul_bytes(self):
        with pytest.raises(ValueError, match="NUL"):
            _sanitize_cli_arg("statistical\x00--help")
