"""Security tests for notification transport validation."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="must not include embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _MockPostContext:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "redirect" if 300 <= self.status < 400 else "ok"


class _MockClientSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        type(self).last_post_kwargs = kwargs
        return _MockPostContext()


class _RedirectingClientSession(_MockClientSession):
    def post(self, *args, **kwargs):
        type(self).last_post_kwargs = kwargs
        return _MockPostContext(status=302)


class TestNotificationTransportSecurity:
    """Validate notification sends use secure transport settings."""

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Security Test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    @pytest.mark.asyncio
    @patch(
        "core.notification_service.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    async def test_slack_disables_redirects(self, _dns, message):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        with patch("core.notification_service.aiohttp.ClientSession", _MockClientSession):
            result = await svc._send_slack(message)

        assert result["success"] is True
        assert _MockClientSession.last_post_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    @patch(
        "core.notification_service.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    async def test_discord_disables_redirects(self, _dns, message):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        with patch("core.notification_service.aiohttp.ClientSession", _MockClientSession):
            result = await svc._send_discord(message)

        assert result["success"] is True
        assert _MockClientSession.last_post_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    @patch(
        "core.notification_service.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    async def test_custom_webhook_rejects_redirect_response(self, _dns, message):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        with patch("core.notification_service.aiohttp.ClientSession", _RedirectingClientSession):
            result = await svc._send_webhook(message)

        assert result["success"] is False
        assert result["error"].startswith("Redirect responses are not allowed")
        assert _RedirectingClientSession.last_post_kwargs["allow_redirects"] is False

    def test_email_rejects_plaintext_auth(self, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = svc._send_email(message)

        assert result["success"] is False
        assert "Refusing to authenticate" in result["error"]

    def test_email_starttls_uses_verified_context(self, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = svc._send_email(message)

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
