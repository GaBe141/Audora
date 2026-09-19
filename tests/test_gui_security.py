"""Security tests for GUI subprocess and webhook input validation."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    validate_demo_mode,
    validate_optional_webhook_url,
    validate_subprocess_args,
)


class TestGuiDemoAllowlist:
    def test_known_modes_are_accepted(self):
        for mode in ALLOWED_DEMO_MODES:
            assert validate_demo_mode(mode) == mode

    def test_rejects_unknown_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            validate_demo_mode("; rm -rf /")

    def test_rejects_non_string_mode(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            validate_demo_mode(["statistical"])


class TestGuiSubprocessArgs:
    def test_accepts_string_argv(self):
        args = ["python", "main.py", "--demo", "statistical"]
        assert validate_subprocess_args(args) == args

    def test_rejects_nul_bytes(self):
        with pytest.raises(ValueError, match="NUL-free"):
            validate_subprocess_args(["python", "main.py\x00--help"])

    def test_rejects_non_string_entries(self):
        with pytest.raises(ValueError, match="NUL-free"):
            validate_subprocess_args(["python", 1])

    def test_rejects_empty_list(self):
        with pytest.raises(ValueError, match="non-empty"):
            validate_subprocess_args([])


class TestGuiWebhookValidation:
    def test_blank_url_is_unset(self):
        assert validate_optional_webhook_url("   ") is None
        assert validate_optional_webhook_url(None) is None

    def test_rejects_http_webhook(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_optional_webhook_url("http://example.com/hook")
