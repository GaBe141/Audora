"""Security tests for notification and webhook safety controls."""

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

    def test_private_webhook_override_disabled_outside_dev(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        monkeypatch.setenv("AUDORA_ENV", "production")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is False

    def test_private_webhook_override_allowed_in_dev(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        monkeypatch.setenv("AUDORA_ENV", "development")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is True


class TestConfigPersistenceSecurity:
    """Ensure persisted notification config does not include secrets."""

    def test_save_config_redacts_secret_fields(self, tmp_path):
        output_path = tmp_path / "notification_config.json"
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        svc.save_config(str(output_path))

        saved = json.loads(output_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]
