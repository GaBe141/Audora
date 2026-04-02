"""Security tests for notification webhook URL validation."""

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


class _FakeSMTPNoStartTLS:
    def __init__(self, *_args, **_kwargs):
        self.logged_in = False
        self.sent = False

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        return False

    def ehlo(self):
        return (250, b"ok")

    def has_extn(self, _name: str) -> bool:
        return False

    def starttls(self, context=None):
        raise RuntimeError(f"Unexpected starttls call with context={context!r}")

    def login(self, *_args, **_kwargs):
        self.logged_in = True

    def send_message(self, _msg):
        self.sent = True


class TestSmtpTransportSecurity:
    def test_rejects_auth_without_tls(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "alerts@example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
                "require_starttls": True,
            }
        )

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTPNoStartTLS)
        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_rejects_server_without_starttls_support(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "alerts@example.com",
                "recipients": ["ops@example.com"],
                "use_tls": True,
            }
        )

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTPNoStartTLS)
        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is False
        assert "does not support STARTTLS" in result["error"]
