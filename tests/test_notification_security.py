"""Security tests for notification webhook URL validation."""

import asyncio
import smtplib
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


class TestEmailTlsSecurity:
    """Validate secure SMTP TLS behavior."""

    def test_email_uses_starttls_with_default_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "noreply@example.com",
                "recipients": ["user@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )

        message = NotificationMessage(
            title="Security test",
            content="TLS verification test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        fake_server = MagicMock()
        with patch.object(smtplib, "SMTP", return_value=fake_server):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        fake_server.starttls.assert_called_once()
        starttls_call = fake_server.starttls.call_args
        assert starttls_call is not None
        context = starttls_call.kwargs.get("context")
        assert context is not None
        assert getattr(context, "check_hostname", False) is True
