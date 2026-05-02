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


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self, calls):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse()


class TestWebhookTransportSecurity:
    """Validate transport hardening on outbound notification sends."""

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)

        monkeypatch.setattr(
            notification_service.aiohttp, "ClientSession", lambda: _FakeSession(calls)
        )

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False

    def test_slack_does_not_follow_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)

        monkeypatch.setattr(
            notification_service.aiohttp, "ClientSession", lambda: _FakeSession(calls)
        )

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False

    def test_discord_does_not_follow_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr(
            notification_service.aiohttp, "ClientSession", lambda: _FakeSession(calls)
        )

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False


class _FakeSMTP:
    starttls_context = None
    login_called = False

    def __init__(self, server, port):
        self.server = server
        self.port = port

    def starttls(self, *, context):
        _FakeSMTP.starttls_context = context

    def login(self, username, password):
        _FakeSMTP.login_called = True

    def send_message(self, msg):
        return None

    def quit(self):
        return None


class TestEmailTransportSecurity:
    """Validate SMTP transport hardening."""

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        _FakeSMTP.starttls_context = None
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "use_tls": True,
            }
        )
        monkeypatch.setattr(notification_service.smtplib, "SMTP", _FakeSMTP)

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert _FakeSMTP.starttls_context is not None
        assert _FakeSMTP.starttls_context.check_hostname is True
        assert _FakeSMTP.starttls_context.verify_mode == notification_service.ssl.CERT_REQUIRED

    def test_smtp_auth_requires_tls(self, monkeypatch):
        _FakeSMTP.login_called = False
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        monkeypatch.setattr(notification_service.smtplib, "SMTP", _FakeSMTP)

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        assert _FakeSMTP.login_called is False
