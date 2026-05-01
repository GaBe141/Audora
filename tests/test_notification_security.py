"""Security tests for notification transport hardening."""

import asyncio
import ssl
from unittest.mock import Mock, patch

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


class _FakeAiohttpResponse:
    def __init__(self, status: int):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "redirect"


class _FakeAiohttpSession:
    post_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append(kwargs)
        return _FakeAiohttpResponse(302)


class TestNotificationTransportHardening:
    """Validate outbound notification transport protections."""

    def setup_method(self):
        _FakeAiohttpSession.post_calls = []

    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _FakeAiohttpSession)
    def test_slack_disables_redirects(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))

        assert result["success"] is False
        assert _FakeAiohttpSession.post_calls[-1]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _FakeAiohttpSession)
    def test_discord_disables_redirects(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))

        assert result["success"] is False
        assert _FakeAiohttpSession.post_calls[-1]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _FakeAiohttpSession)
    def test_custom_webhook_disables_redirects(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom"

        result = asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert result["success"] is False
        assert _FakeAiohttpSession.post_calls[-1]["allow_redirects"] is False

    @patch("core.notification_service.smtplib.SMTP")
    def test_smtp_starttls_uses_validating_ssl_context(self, mock_smtp):
        smtp_instance = Mock()
        mock_smtp.return_value = smtp_instance
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

        result = asyncio.run(svc._send_email(self._message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        context = smtp_instance.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    @patch("core.notification_service.smtplib.SMTP")
    def test_smtp_refuses_plaintext_auth(self, mock_smtp):
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

        result = asyncio.run(svc._send_email(self._message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert not mock_smtp.return_value.login.called
