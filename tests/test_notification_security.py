"""Security tests for notification service hardening."""

import asyncio
from unittest.mock import patch

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


class TestEmailTransportSecurity:
    """Validate secure SMTP behavior for outbound email notifications."""

    def test_send_email_enforces_tls_certificate_validation(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "from_address": "noreply@example.com",
                "recipients": [" alice@example.com ", "", "bob@example.com"],
                "use_tls": True,
                "timeout": 12,
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="Testing TLS setup",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        tls_context = object()
        with (
            patch(
                "core.notification_service.ssl.create_default_context", return_value=tls_context
            ) as context_mock,
            patch("core.notification_service.smtplib.SMTP") as smtp_mock,
        ):
            smtp_instance = smtp_mock.return_value
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp_mock.assert_called_once_with("smtp.example.com", 587, timeout=12)
        context_mock.assert_called_once_with()
        smtp_instance.starttls.assert_called_once_with(context=tls_context)
        smtp_instance.login.assert_called_once_with("user", "pass")
        smtp_instance.send_message.assert_called_once()
        assert smtp_instance.send_message.call_args.kwargs["to_addrs"] == [
            "alice@example.com",
            "bob@example.com",
        ]
