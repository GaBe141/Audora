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


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return "ok"


class _FakeSession:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return _FakeResponse(self.status)


class _FakeSMTP:
    instances = []

    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.starttls_context = None
        self.login_called = False
        self.send_called = False
        self.quit_called = False
        self.__class__.instances.append(self)

    def starttls(self, context=None):
        self.starttls_context = context

    def login(self, username, password):
        self.login_called = True

    def send_message(self, msg):
        self.send_called = True

    def quit(self):
        self.quit_called = True


def _message(channel):
    return NotificationMessage(
        title="Security test",
        content="Test content",
        priority=NotificationPriority.HIGH,
        channels=[channel],
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
            svc._validate_webhook_url("https://user:password@example.com/webhook")


class TestNotificationTransportSecurity:
    """Validate outbound transport security controls."""

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        fake_session = _FakeSession(status=200)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert fake_session.calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        fake_session = _FakeSession(status=204)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert fake_session.calls[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        fake_session = _FakeSession(status=200)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert fake_session.calls[0]["kwargs"]["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "password",
                "recipients": ["security@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        smtp = _FakeSMTP.instances[0]
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.check_hostname is True
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.login_called is True

    def test_smtp_auth_without_tls_is_rejected(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "password",
                "recipients": ["security@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        smtp = _FakeSMTP.instances[0]
        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert smtp.login_called is False
        assert smtp.send_called is False
        assert smtp.quit_called is True
