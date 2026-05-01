"""Security tests for notification transport hardening."""

import ssl
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

    def test_rejects_webhook_urls_with_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _MockResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _MockClientSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        type(self).last_post_kwargs = kwargs
        return _MockResponse()


def _message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="content",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


@pytest.mark.asyncio
class TestWebhookTransports:
    async def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, *, allow_private=False: url
        )

        with patch("core.notification_service.aiohttp.ClientSession", _MockClientSession):
            result = await svc._send_slack(_message(NotificationChannel.SLACK))

        assert result["success"] is True
        assert _MockClientSession.last_post_kwargs["allow_redirects"] is False

    async def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, *, allow_private=False: url
        )

        with patch("core.notification_service.aiohttp.ClientSession", _MockClientSession):
            result = await svc._send_discord(_message(NotificationChannel.DISCORD))

        assert result["success"] is True
        assert _MockClientSession.last_post_kwargs["allow_redirects"] is False

    async def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)

        with patch("core.notification_service.aiohttp.ClientSession", _MockClientSession):
            result = await svc._send_webhook(_message(NotificationChannel.WEBHOOK))

        assert result["success"] is True
        assert _MockClientSession.last_post_kwargs["allow_redirects"] is False


@pytest.mark.asyncio
class TestEmailTransportSecurity:
    async def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )

        result = await svc._send_email(_message(NotificationChannel.EMAIL))

        assert result["success"] is False
        assert "TLS" in result["error"]

    async def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )

        smtp = MagicMock()
        smtp.starttls = MagicMock()
        smtp.login = MagicMock()
        smtp.send_message = MagicMock()
        smtp.quit = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(_message(NotificationChannel.EMAIL))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
