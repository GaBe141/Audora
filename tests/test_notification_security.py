"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import MagicMock, patch

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


class FakeAiohttpResponse:
    def __init__(self, status=200, body="ok"):
        self.status = status
        self.body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self.body


class FakeAiohttpSession:
    calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeAiohttpResponse()


class TestNotificationTransportSecurity:
    """Validate SSRF and SMTP protections at send time."""

    @pytest.fixture(autouse=True)
    def reset_calls(self):
        FakeAiohttpSession.calls = []

    def make_message(self):
        return NotificationMessage(
            title="Security test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    def test_slack_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeAiohttpSession)

        result = asyncio.run(svc._send_slack(self.make_message()))

        assert result["success"] is True
        assert FakeAiohttpSession.calls[0][1]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeAiohttpSession)

        result = asyncio.run(svc._send_discord(self.make_message()))

        assert result["success"] is True
        assert FakeAiohttpSession.calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeAiohttpSession)

        result = asyncio.run(svc._send_webhook(self.make_message()))

        assert result["success"] is True
        assert FakeAiohttpSession.calls[0][1]["allow_redirects"] is False

    def test_smtp_auth_without_tls_is_rejected(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self.make_message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_smtp_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        server = MagicMock()
        ssl_context = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch("core.notification_service.ssl.create_default_context", return_value=ssl_context),
        ):
            result = asyncio.run(svc._send_email(self.make_message()))

        assert result["success"] is True
        server.starttls.assert_called_once_with(context=ssl_context)
        server.login.assert_called_once_with("user", "secret")
