"""Security tests for notification delivery protections."""

import asyncio

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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeSMTP:
    """Small SMTP test double that records TLS usage."""

    instances = []

    def __init__(self, _host, _port):
        self.started_tls = False
        self.logged_in = False
        self.sent = False
        self.quit_called = False
        self.__class__.instances.append(self)

    def starttls(self, context=None):
        self.started_tls = context is not None

    def login(self, _username, _password):
        self.logged_in = True

    def send_message(self, _msg):
        self.sent = True

    def quit(self):
        self.quit_called = True


class TestEmailSecurity:
    """Validate SMTP transport security choices."""

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result == {"success": False, "error": "SMTP authentication requires TLS"}

    def test_smtp_starttls_uses_default_ssl_context(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        smtp = _FakeSMTP.instances[0]
        assert result["success"] is True
        assert smtp.started_tls is True
        assert smtp.logged_in is True
        assert smtp.sent is True
        assert smtp.quit_called is True
