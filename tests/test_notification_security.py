"""Security tests for notification delivery hardening."""

import asyncio
import ssl

import pytest

from core import notification_service
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


class _FakeResponse:
    """Async context manager that behaves like an aiohttp response."""

    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeClientSession:
    """Capture outbound POST kwargs without performing network I/O."""

    def __init__(self):
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return _FakeResponse()


class TestWebhookDeliveryHardening:
    """Validate webhook delivery options that prevent redirect-based SSRF."""

    def _service_with_fake_session(self, monkeypatch):
        svc = EnhancedNotificationService()
        fake_session = _FakeClientSession()

        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", lambda: fake_session)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_kwargs: url)

        message = NotificationMessage(
            title="Security test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        return svc, fake_session, message

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        svc, fake_session, message = self._service_with_fake_session(monkeypatch)
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        svc, fake_session, message = self._service_with_fake_session(monkeypatch)
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        svc, fake_session, message = self._service_with_fake_session(monkeypatch)
        svc.config["webhook"]["url"] = "https://example.com/custom"

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False


class _FakeSMTP:
    """Capture SMTP security behavior without opening a socket."""

    instances = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.starttls_context = None
        self.login_args = None
        self.sent = False
        self.closed = False
        self.__class__.instances.append(self)

    def starttls(self, *, context=None):
        self.starttls_context = context

    def login(self, username, password):
        self.login_args = (username, password)

    def send_message(self, _message):
        self.sent = True

    def quit(self):
        self.closed = True


class TestEmailDeliveryHardening:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_smtp_starttls_uses_verified_default_context(self, monkeypatch):
        tls_context = ssl.create_default_context()
        _FakeSMTP.instances = []
        monkeypatch.setattr(notification_service.smtplib, "SMTP", _FakeSMTP)
        monkeypatch.setattr(notification_service.ssl, "create_default_context", lambda: tls_context)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        smtp = _FakeSMTP.instances[0]
        assert result["success"] is True
        assert smtp.starttls_context is tls_context
        assert smtp.login_args == ("user", "pass")
        assert smtp.sent is True

    def test_smtp_refuses_credentials_without_tls(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr(notification_service.smtplib, "SMTP", _FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result == {
            "success": False,
            "error": "Refusing to send SMTP credentials without TLS",
        }
        assert _FakeSMTP.instances == []
