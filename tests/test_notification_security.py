"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


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
            svc._validate_webhook_url("https://user:token@example.com/webhook")

    def test_sanitize_header_strips_crlf(self):
        svc = EnhancedNotificationService()
        sanitized = svc._sanitize_header("Alert\r\nBcc: attacker@example.com")
        assert "\r" not in sanitized
        assert "\n" not in sanitized
        assert "Alert" in sanitized

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_config_path_is_confined(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc._resolve_config_path(str(tmp_path / "evil.json"))
