"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

import core.notification_service as notification_service
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportHardening:
    """Ensure notification transport uses secure network settings."""

    def test_webhook_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        captured_kwargs: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return "ok"

        class FakeRequestContext:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeClientSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeRequestContext()

        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", lambda: FakeClientSession())

        message = NotificationMessage(
            title="security test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert captured_kwargs.get("allow_redirects") is False

    def test_email_send_uses_tls_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "music-discovery@example.com",
            "recipients": ["security@example.com"],
            "use_tls": True,
        }

        captured: dict[str, object] = {"tls_context": None, "sent": False}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def ehlo(self):
                return None

            def starttls(self, context=None):
                captured["tls_context"] = context
                return (220, b"ready")

            def login(self, *_args, **_kwargs):
                return None

            def send_message(self, _msg):
                captured["sent"] = True
                return {}

        monkeypatch.setattr(notification_service.smtplib, "SMTP", FakeSMTP)

        message = NotificationMessage(
            title="email security",
            content="test body",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert captured["sent"] is True
        assert captured["tls_context"] is not None
