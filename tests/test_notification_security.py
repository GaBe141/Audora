"""Security tests for notification webhook URL validation."""

import pytest

from core.notification_service import EnhancedNotificationService
from gui.app import app, save_settings


class TestWebhookUrlValidation:
    """Validate SSRF protections for outbound webhooks."""

    def test_rejects_non_https_urls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="HTTPS"):
            svc._validate_webhook_url("http://example.com/webhook")

    def test_rejects_localhost_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://localhost/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_private_ip_even_when_allow_flag_is_requested(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook", allow_private=True)

    def test_private_webhook_env_flag_is_ignored(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is False


class TestNotificationConfigPersistence:
    """Validate that saved notification settings do not persist credentials."""

    def test_save_config_strips_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = config_path.read_text()
        assert "smtp-secret" not in saved
        assert "sms-key" not in saved
        assert "sms-secret" not in saved
        assert "webhook-secret" not in saved

    def test_save_config_leaves_public_channel_settings(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["webhook"]["url"] = "https://hooks.example.com/audora"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = config_path.read_text()
        assert "smtp.example.com" in saved
        assert "https://hooks.example.com/audora" in saved


class TestGuiNotificationSettings:
    """Validate GUI notification settings do not accept or persist secrets."""

    def test_save_settings_rejects_missing_admin_token(self, monkeypatch):
        monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)

        result = save_settings(
            1,
            "",
            "",
            "",
            "smtp.example.com",
            587,
            "user",
            None,
        )

        assert "AUDORA_GUI_ADMIN_TOKEN" in result

    def test_settings_layout_does_not_accept_smtp_password(self):
        layout_repr = repr(app.layout)
        assert "input-smtp-pass" not in layout_repr
