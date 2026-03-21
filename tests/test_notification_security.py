"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

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

    def test_email_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "recipients": ["alerts@example.com"],
            "from_address": "audora@example.com",
            "use_tls": True,
            "username": "",
            "password": "",
        }
        message = NotificationMessage(
            title="Security Test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        smtp_mock = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_mock):
            asyncio.run(svc._send_email(message))

        _, kwargs = smtp_mock.starttls.call_args
        assert "context" in kwargs
        assert isinstance(kwargs["context"], ssl.SSLContext)
