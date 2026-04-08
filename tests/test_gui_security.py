"""Security tests for GUI admin-only operations."""

import os
from importlib import import_module

gui_app = import_module("gui.app")


class TestGuiAdminAuthorization:
    """Validate GUI admin token enforcement."""

    def test_is_authorized_admin_rejects_when_token_not_configured(self, monkeypatch):
        monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)
        assert gui_app._is_authorized_admin("any") is False

    def test_is_authorized_admin_rejects_missing_or_wrong_token(self, monkeypatch):
        monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected")
        assert gui_app._is_authorized_admin("") is False
        assert gui_app._is_authorized_admin(None) is False
        assert gui_app._is_authorized_admin("wrong") is False

    def test_is_authorized_admin_accepts_correct_token(self, monkeypatch):
        monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected")
        assert gui_app._is_authorized_admin("expected") is True


class TestGuiSaveSettings:
    """Ensure save callback blocks unauthorized changes."""

    def test_save_settings_rejects_unauthorized(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected")
        cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = gui_app.save_settings(
                1,
                "https://hooks.slack.com/services/a/b/c",
                "",
                "",
                "smtp.example.com",
                587,
                "user",
                "ignored-password",
                "wrong-token",
            )
            assert result == "Unauthorized"
        finally:
            os.chdir(cwd)
