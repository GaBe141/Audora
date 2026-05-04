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


class _MockResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _MockClientSession:
    post_calls = []

    def __init__(self):
        self.response = _MockResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return self.response


class TestNotificationTransportHardening:
    """Verify external notification transports do not follow redirects."""

    @pytest.mark.parametrize(
        ("channel", "config_key", "url_key"),
        [
            (NotificationChannel.SLACK, "slack", "webhook_url"),
            (NotificationChannel.DISCORD, "discord", "webhook_url"),
            (NotificationChannel.WEBHOOK, "webhook", "url"),
        ],
    )
    @pytest.mark.asyncio
    async def test_webhook_channels_disable_redirects(self, channel, config_key, url_key):
        _MockClientSession.post_calls = []
        svc = EnhancedNotificationService()
        svc.config[config_key][url_key] = "https://hooks.example.test/webhook"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", _MockClientSession),
        ):
            await svc.channel_handlers[channel](message)

        assert _MockClientSession.post_calls
        assert _MockClientSession.post_calls[0][1]["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_rejects_redirect_statuses(self):
        class RedirectSession(_MockClientSession):
            def __init__(self):
                self.response = _MockResponse(status=302)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.test/webhook"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", RedirectSession),
        ):
            result = await svc._send_webhook(message)

        assert result["success"] is False
        assert "Redirects are not allowed" in result["error"]


class TestEmailTransportHardening:
    """Verify SMTP credentials are not sent without verified TLS."""

    @pytest.mark.asyncio
    async def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.test",
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.test"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is False
        assert "SMTP authentication requires TLS" in result["error"]

    @pytest.mark.asyncio
    async def test_starttls_uses_default_ssl_context(self):
        smtp = MagicMock()
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.test",
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.test"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
