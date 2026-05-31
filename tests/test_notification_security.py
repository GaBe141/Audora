"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import patch

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


class _FakeClientSession:
    post_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, _url, **kwargs):
        self.post_calls.append(kwargs)
        return _FakeResponse()


class TestWebhookTransportSecurity:
    """Validate outbound webhook transport protections."""

    def setup_method(self):
        _FakeClientSession.post_calls = []

    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="Transport hardening",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    def test_slack_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)

        result = asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert _FakeClientSession.post_calls[0]["allow_redirects"] is False

    def test_discord_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)

        result = asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert _FakeClientSession.post_calls[0]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)

        result = asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert _FakeClientSession.post_calls[0]["allow_redirects"] is False


class _FakeSMTP:
    instances = []

    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.starttls_context = None
        self.login_called = False
        self.message_sent = False
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def starttls(self, *, context=None):
        self.starttls_context = context

    def login(self, username, password):
        self.login_called = True

    def send_message(self, msg):
        self.message_sent = True


class TestEmailTransportSecurity:
    """Validate SMTP transport protections."""

    def setup_method(self):
        _FakeSMTP.instances = []

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Email security test",
            content="<b>must be escaped</b>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

    def test_smtp_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )

        with patch("core.notification_service.smtplib.SMTP", _FakeSMTP):
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert isinstance(_FakeSMTP.instances[0].starttls_context, ssl.SSLContext)
        assert _FakeSMTP.instances[0].login_called is True

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
