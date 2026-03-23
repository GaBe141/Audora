"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
import types

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


class TestNotificationSecurityHardening:
    """Regression tests for hardened notification delivery behavior."""

    def test_message_key_is_deterministic_sha256(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Security alert",
            content="An event occurred",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        key_a = svc._generate_message_key(message)
        key_b = svc._generate_message_key(message)
        assert key_a == key_b
        assert len(key_a) == 64
        assert all(ch in "0123456789abcdef" for ch in key_a)

    def test_webhook_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)

        observed_kwargs = {}

        class _DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

        class _DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, *args, **kwargs):
                observed_kwargs.update(kwargs)
                return _DummyResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _DummySession)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientTimeout",
            lambda total: types.SimpleNamespace(total=total),
        )

        message = NotificationMessage(
            title="Webhook test",
            content="Testing redirect behavior",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert observed_kwargs.get("allow_redirects") is False

    def test_email_starttls_uses_verifying_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "noreply@example.com",
            "recipients": ["dev@example.com"],
            "use_tls": True,
        }

        captured_context = {"value": None}

        class _DummySmtp:
            def __init__(self, host, port):
                self.host = host
                self.port = port

            def starttls(self, context=None):
                captured_context["value"] = context

            def login(self, username, password):
                return None

            def send_message(self, message):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySmtp)

        message = NotificationMessage(
            title="Email test",
            content="TLS validation test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert isinstance(captured_context["value"], ssl.SSLContext)
