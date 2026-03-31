"""Security tests for notification webhook URL validation."""

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


class TestNotificationSecretPersistence:
    """Validate that secrets are not written to config files."""

    def test_save_config_strips_sensitive_fields(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer leaked-token"
        svc.config["webhook"]["auth_token"] = "do-not-persist"

        out_path = tmp_path / "notification_config.json"
        svc.save_config(str(out_path))

        persisted = json.loads(out_path.read_text(encoding="utf-8"))
        assert persisted["email"]["password"] == ""
        assert persisted["sms"]["api_key"] == ""
        assert persisted["sms"]["api_secret"] == ""
        assert "Authorization" not in persisted["webhook"]["headers"]
        assert "auth_token" not in persisted["webhook"]

    def test_webhook_headers_ignore_static_auth_and_use_env_token(self, monkeypatch):
        svc = EnhancedNotificationService()
        webhook_config = {
            "headers": {"Content-Type": "application/json", "Authorization": "Bearer stale"},
            "auth_token_env": "WEBHOOK_TOKEN",
        }

        monkeypatch.setenv("WEBHOOK_TOKEN", "fresh-token")
        headers = svc._build_webhook_headers(webhook_config)
        assert headers["Authorization"] == "Bearer fresh-token"

        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        headers = svc._build_webhook_headers(webhook_config)
        assert "Authorization" not in headers
