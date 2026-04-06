"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import MagicMock, patch

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


class TestEmailTlsSecurity:
    """Validate secure SMTP transport behavior."""

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    def test_send_email_uses_starttls_with_context(self, smtp_cls, create_ctx):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["recipients"] = ["to@example.com"]
        svc.config["email"]["from_address"] = "from@example.com"
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "pass"
        svc.config["email"]["use_tls"] = True

        smtp_obj = MagicMock()
        smtp_cls.return_value.__enter__.return_value = smtp_obj
        tls_context = MagicMock()
        create_ctx.return_value = tls_context

        from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority

        msg = NotificationMessage(
            title="test",
            content="test body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        create_ctx.assert_called_once()
        smtp_obj.starttls.assert_called_once_with(context=tls_context)
