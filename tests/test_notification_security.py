"""Security tests for notification service safeguards."""

import asyncio
import ssl

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
    """Validate SMTP transport security behavior."""

    def test_email_uses_verified_tls_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        svc.config["email"]["from_address"] = "audora@example.com"
        svc.config["email"]["use_tls"] = True

        captured: dict[str, ssl.SSLContext] = {}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                return

            def starttls(self, *, context=None):
                captured["context"] = context
                return

            def login(self, *_args, **_kwargs):
                return

            def send_message(self, *_args, **_kwargs):
                return

            def quit(self):
                return

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        message = NotificationMessage(
            title="Security test",
            content="TLS test",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc.send_notification(message))

        assert result["delivered"] is True
        tls_context = captured.get("context")
        assert isinstance(tls_context, ssl.SSLContext)
        assert tls_context.verify_mode == ssl.CERT_REQUIRED
        assert tls_context.check_hostname is True
