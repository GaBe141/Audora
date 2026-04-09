"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import Mock

import pytest

from core.notification_service import EnhancedNotificationService
from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority


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


class _DummySmtp:
    """Minimal SMTP test double used to validate TLS behavior."""

    def __init__(self):
        self.started_tls = False
        self.tls_context = None
        self.sent_message = False
        self.logged_in = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self):
        return None

    def has_extn(self, name: str) -> bool:
        return name.lower() == "starttls"

    def starttls(self, context=None):
        self.started_tls = True
        self.tls_context = context
        return (220, "ready")

    def login(self, _user, _password):
        self.logged_in = True

    def send_message(self, *_args, **_kwargs):
        self.sent_message = True


class _NoStartTlsSmtp(_DummySmtp):
    def has_extn(self, _name: str) -> bool:
        return False


def test_email_requires_starttls(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"] = {
        "smtp_server": "smtp.example.com",
        "port": 587,
        "username": "user",
        "password": "pass",
        "from_address": "from@example.com",
        "recipients": ["to@example.com"],
        "use_tls": True,
    }

    monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *a, **k: _NoStartTlsSmtp())
    message = NotificationMessage(
        title="test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )

    result = asyncio.run(svc._send_email(message))
    assert result["success"] is False
    assert "STARTTLS" in result["error"]


def test_email_uses_verified_tls_context(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"] = {
        "smtp_server": "smtp.example.com",
        "port": 587,
        "username": "user",
        "password": "pass",
        "from_address": "from@example.com",
        "recipients": ["to@example.com"],
        "use_tls": True,
    }

    smtp = _DummySmtp()
    monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *a, **k: smtp)

    created_context = Mock(spec=ssl.SSLContext)
    created_context.minimum_version = None
    monkeypatch.setattr(
        "core.notification_service.ssl.create_default_context",
        lambda: created_context,
    )

    message = NotificationMessage(
        title="test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )

    result = asyncio.run(svc._send_email(message))
    assert result["success"] is True
    assert smtp.started_tls is True
    assert smtp.tls_context is created_context
    assert created_context.minimum_version == ssl.TLSVersion.TLSv1_2
