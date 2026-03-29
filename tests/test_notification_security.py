"""Security tests for notification transport hardening and webhook validation."""

import asyncio
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


class TestEmailSecurity:
    """Validate SMTP TLS and header-injection protections."""

    def test_sanitize_header_rejects_crlf_injection(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header_value("Hello\r\nInjected: bad", "Subject") == "HelloInjected: bad"

    def test_send_email_uses_starttls_with_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
            "timeout_seconds": 5,
        }

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        smtp_instance = MagicMock()
        smtp_instance.__enter__.return_value = smtp_instance

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance), patch(
            "core.notification_service.ssl.create_default_context", return_value=MagicMock()
        ) as context_factory:
            result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        context_factory.assert_called_once()
        smtp_instance.starttls.assert_called_once_with(context=context_factory.return_value)
        smtp_instance.send_message.assert_called_once()
