"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import MagicMock

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class FakeResponseContext:
    def __init__(self, status: int = 200):
        self.response = MagicMock()
        self.response.status = status
        self.response.text = MagicMock(return_value="")

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeClientSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return FakeResponseContext(self.status)


class TestNotificationTransportSecurity:
    """Validate secure outbound transport options."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Security Test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/webhook"
        svc._validate_webhook_url = MagicMock(side_effect=lambda url, allow_private=False: url)
        fake_session = FakeClientSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_slack(self._message()))

        assert result["success"] is True
        assert fake_session.calls[0][1]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        svc._validate_webhook_url = MagicMock(side_effect=lambda url, allow_private=False: url)
        fake_session = FakeClientSession(status=204)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_discord(self._message()))

        assert result["success"] is True
        assert fake_session.calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://webhook.example/notify"
        svc._validate_webhook_url = MagicMock(side_effect=lambda url, allow_private=False: url)
        fake_session = FakeClientSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: fake_session
        )

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert fake_session.calls[0][1]["allow_redirects"] is False

    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )
        smtp = MagicMock()
        context = object()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", MagicMock(return_value=smtp))
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            MagicMock(return_value=context),
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        smtp.starttls.assert_called_once_with(context=context)

    def test_email_rejects_plaintext_auth(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        smtp_factory = MagicMock()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", smtp_factory)

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        smtp_factory.assert_not_called()
