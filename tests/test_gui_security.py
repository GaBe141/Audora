"""Security tests for GUI-sensitive callbacks."""

import importlib

import pytest


@pytest.fixture
def gui_app_module(monkeypatch):
    """Load gui.app with deterministic security env vars for callback tests."""
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "test-admin-token")
    module = importlib.import_module("gui.app")
    module = importlib.reload(module)
    return module


class TestGuiSensitiveAuthorization:
    """Ensure sensitive GUI actions require an admin token."""

    def test_save_settings_rejects_missing_token(self, gui_app_module):
        result = gui_app_module.save_settings(
            1,
            "https://hooks.slack.com/services/T/A/B",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert "Unauthorized" in result

    def test_save_settings_accepts_valid_token(self, gui_app_module, monkeypatch):
        class _FakeService:
            def __init__(self):
                self.config = {
                    "slack": {},
                    "discord": {},
                    "webhook": {},
                    "email": {},
                }
                self.saved = False

            def save_config(self):
                self.saved = True

        monkeypatch.setattr(
            "core.notification_service.EnhancedNotificationService",
            _FakeService,
        )

        result = gui_app_module.save_settings(
            1,
            "https://hooks.slack.com/services/T/A/B",
            None,
            None,
            None,
            None,
            None,
            None,
            "test-admin-token",
        )
        assert result == "Saved"
