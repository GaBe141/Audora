"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

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


class _DummySMTP:
    """In-memory SMTP stub used for secure email delivery tests."""

    instances: list["_DummySMTP"] = []

    def __init__(self, *args, **kwargs):
        self.starttls_context = None
        self.logged_in = False
        self.message_sent = False
        self.quit_called = False
        _DummySMTP.instances.append(self)

    def ehlo(self):
        return None

    def starttls(self, context=None):
        self.starttls_context = context
        return None

    def login(self, _username, _password):
        self.logged_in = True
        return None

    def send_message(self, _message):
        self.message_sent = True
        return None

    def quit(self):
        self.quit_called = True
        return None


class TestEmailTlsSecurity:
    """Validate secure SMTP behavior for email notifications."""

    def test_send_email_uses_verified_tls_context(self, monkeypatch):
        _DummySMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["alerts@example.com"],
                "use_tls": True,
                "username": "user",
                "password": "pass",
            }
        )
        msg = NotificationMessage(
            title="Security test",
            content="TLS should be enabled",
            priority=NotificationPriority.HIGH,
            channels=[],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        smtp = _DummySMTP.instances[-1]
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.logged_in is True
        assert smtp.message_sent is True

    def test_send_email_rejects_plaintext_authentication(self, monkeypatch):
        _DummySMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "pass",
            }
        )
        msg = NotificationMessage(
            title="Security test",
            content="Must reject auth without TLS",
            priority=NotificationPriority.HIGH,
            channels=[],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp = _DummySMTP.instances[-1]
        assert smtp.starttls_context is None
        assert smtp.logged_in is False
        assert smtp.message_sent is False
        assert smtp.quit_called is True
