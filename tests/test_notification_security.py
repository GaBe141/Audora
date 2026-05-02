"""Security tests for notification transport hardening."""

import asyncio
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


class _PostRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _MockResponse()


class _MockResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _MockSession:
    def __init__(self, recorder):
        self.post = recorder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


class TestWebhookTransportHardening:
    """Validate webhook sends do not follow redirects after URL validation."""

    def test_slack_send_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/services/abc"
        recorder = _PostRecorder()
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_MockSession(recorder)),
        ):
            result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert recorder.calls[0][1]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.test/api/webhooks/abc"
        recorder = _PostRecorder()
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["discord"]["webhook_url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_MockSession(recorder)),
        ):
            result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert recorder.calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://webhook.test/notify"
        recorder = _PostRecorder()
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_MockSession(recorder)),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert recorder.calls[0][1]["allow_redirects"] is False


class TestEmailTransportHardening:
    """Validate SMTP credentials are only sent after verified STARTTLS."""

    def test_rejects_smtp_auth_without_tls(self):
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
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "Refusing to send SMTP credentials without TLS" in result["error"]
        smtp.login.assert_not_called()

    def test_starttls_uses_verified_ssl_context(self):
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
        smtp = MagicMock()
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
