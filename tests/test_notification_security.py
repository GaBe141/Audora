"""Security tests for notification webhook URL validation and config safety."""

import json

import pytest

from core.notification_service import EnhancedNotificationService


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

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationConfigPersistence:
    """Validate secure defaults for persisted notification configuration."""

    def test_save_config_omits_smtp_password_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDORA_ALLOW_PLAINTEXT_SMTP_PASSWORD_SAVE", raising=False)
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret-password"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert "password" not in saved["email"]

    def test_save_config_can_persist_smtp_password_when_explicitly_enabled(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("AUDORA_ALLOW_PLAINTEXT_SMTP_PASSWORD_SAVE", "true")
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret-password"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["email"]["password"] == "super-secret-password"
