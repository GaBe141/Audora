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


def test_save_config_can_omit_plaintext_secrets(tmp_path):
    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "smtp-secret"
    svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/token"
    svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/token"
    svc.config["webhook"]["url"] = "https://example.com/hook"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"
    svc.config["sms"]["api_key"] = "sms-key"
    svc.config["sms"]["api_secret"] = "sms-secret"

    config_path = tmp_path / "notification_config.json"
    svc.save_config(str(config_path), include_secrets=False)

    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert persisted["email"]["password"] == ""
    assert persisted["slack"]["webhook_url"] == ""
    assert persisted["discord"]["webhook_url"] == ""
    assert persisted["webhook"]["url"] == ""
    assert persisted["webhook"]["headers"]["Authorization"] == ""
    assert persisted["sms"]["api_key"] == ""
    assert persisted["sms"]["api_secret"] == ""
