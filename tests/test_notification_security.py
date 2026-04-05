"""Security tests for notification service hardening."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationConfigSanitization:
    """Validate secrets are not persisted to notification config."""

    def test_save_config_strips_sensitive_fields(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret-password"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"
        svc.config["webhook"]["headers"] = {
            "Content-Type": "application/json",
            "Authorization": "Bearer should-not-be-saved",
            "X-Api-Key": "api-key-should-not-be-saved",
        }

        output_file = tmp_path / "notification_config.json"
        svc.save_config(str(output_file))

        saved = json.loads(output_file.read_text(encoding="utf-8"))
        assert "password" not in saved.get("email", {})
        assert "api_key" not in saved.get("sms", {})
        assert "api_secret" not in saved.get("sms", {})
        assert "Authorization" not in saved.get("webhook", {}).get("headers", {})
        assert "X-Api-Key" not in saved.get("webhook", {}).get("headers", {})

    def test_webhook_headers_use_environment_token(self, monkeypatch):
        svc = EnhancedNotificationService()
        headers = {"Content-Type": "application/json", "Authorization": "Bearer static-token"}

        monkeypatch.setenv("WEBHOOK_TOKEN", "env-token")
        built_headers = svc._get_webhook_headers({"headers": headers})
        assert built_headers["Authorization"] == "Bearer env-token"
