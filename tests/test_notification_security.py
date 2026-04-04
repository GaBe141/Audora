"""Security tests for notification webhook URL validation."""

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
    """Validate secure TLS behavior for SMTP notifications."""

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        class FakeSMTP:
            instances = []

            def __init__(self, *_args, **_kwargs):
                self.starttls_context = None
                self.ehlo_calls = 0
                self.logged_in = False
                self.sent = False
                FakeSMTP.instances.append(self)

            def ehlo(self):
                self.ehlo_calls += 1

            def starttls(self, context=None):
                self.starttls_context = context

            def login(self, _username, _password):
                self.logged_in = True

            def send_message(self, _msg):
                self.sent = True

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "audora@example.com",
            "recipients": ["security@example.com"],
            "use_tls": True,
        }

        msg = NotificationMessage(
            title="TLS test",
            content="Validate TLS context",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is True
        smtp = FakeSMTP.instances[0]
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.ehlo_calls == 2
