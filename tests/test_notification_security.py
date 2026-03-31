"""Security tests for notification service hardening."""

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


class TestWebhookRedirectHandling:
    """Ensure outbound webhook sends do not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        # Avoid DNS/network lookup; URL policy is tested separately above.
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        called: dict[str, object] = {}

        class _FakeResponse:
            status = 200

            async def text(self):
                return ""

        class _FakeRequestContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                called["kwargs"] = kwargs
                return _FakeRequestContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _FakeSession())

        message = NotificationMessage(
            title="Security test",
            content="Validate redirect controls",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert called["kwargs"]["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        called: dict[str, object] = {}

        class _FakeResponse:
            status = 200

            async def text(self):
                return ""

        class _FakeRequestContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                called["kwargs"] = kwargs
                return _FakeRequestContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _FakeSession())

        message = NotificationMessage(
            title="Slack security test",
            content="Validate redirect controls",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert called["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        called: dict[str, object] = {}

        class _FakeResponse:
            status = 204

            async def text(self):
                return ""

        class _FakeRequestContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                called["kwargs"] = kwargs
                return _FakeRequestContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _FakeSession())

        message = NotificationMessage(
            title="Discord security test",
            content="Validate redirect controls",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert called["kwargs"]["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Ensure secure SMTP transport settings are used."""

    def test_email_starttls_uses_verifying_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["security@example.com"],
                "from_address": "noreply@example.com",
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )

        sentinel_context = object()
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: sentinel_context,
        )

        called: dict[str, object] = {}

        class _FakeSMTP:
            def __init__(self, host, port):
                called["host"] = host
                called["port"] = port

            def starttls(self, context=None):
                called["tls_context"] = context

            def login(self, username, password):
                called["login"] = (username, password)

            def send_message(self, msg):
                called["subject"] = msg["Subject"]

            def quit(self):
                called["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        message = NotificationMessage(
            title="Email security test",
            content="Validate TLS context",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert called["tls_context"] is sentinel_context
