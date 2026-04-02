"""Security tests for notification transport and webhook URL validation."""

from unittest.mock import MagicMock

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
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


@pytest.mark.asyncio
async def test_email_send_rejects_missing_starttls_support(monkeypatch):
    """Email transport must fail closed when STARTTLS is required but unavailable."""
    svc = EnhancedNotificationService()
    svc.config["email"] = {
        "smtp_server": "smtp.example.test",
        "port": 587,
        "username": "user",
        "password": "pass",
        "from_address": "from@example.test",
        "recipients": ["to@example.test"],
        "use_tls": True,
    }

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            self.login_called = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def ehlo(self):
            return None

        def has_extn(self, ext):
            return False

        def starttls(self, context=None):
            raise AssertionError("starttls should not be called without STARTTLS extension")

        def login(self, username, password):
            self.login_called = True

        def send_message(self, msg):
            raise AssertionError("send_message should not be called when STARTTLS is unavailable")

    monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

    msg = NotificationMessage(
        title="TLS Test",
        content="Test body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )
    result = await svc._send_email(msg)
    assert result["success"] is False
    assert "STARTTLS" in result["error"]
