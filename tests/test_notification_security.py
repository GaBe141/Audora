"""Security tests for notification transport hardening."""

from unittest.mock import AsyncMock, MagicMock, patch

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


class _MockPostContext:
    def __init__(self, recorder: dict):
        self.recorder = recorder

    async def __aenter__(self):
        response = AsyncMock()
        response.status = 200
        response.text.return_value = "ok"
        return response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _MockSession:
    def __init__(self, recorder: dict):
        self.recorder = recorder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.recorder["url"] = url
        self.recorder["kwargs"] = kwargs
        return _MockPostContext(self.recorder)


class TestNotificationTransportSecurity:
    """Validate outbound transports do not bypass URL validation."""

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Security alert",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    @patch("core.notification_service.socket.getaddrinfo")
    @pytest.mark.asyncio
    async def test_webhook_disables_redirect_following(self, mock_getaddrinfo, message):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        recorder: dict = {}

        with patch("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(recorder)):
            result = await svc._send_webhook(message)

        assert result["success"] is True
        assert recorder["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @pytest.mark.asyncio
    async def test_slack_disables_redirect_following(self, mock_getaddrinfo, message):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        recorder: dict = {}

        with patch("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(recorder)):
            result = await svc._send_slack(message)

        assert result["success"] is True
        assert recorder["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @pytest.mark.asyncio
    async def test_discord_disables_redirect_following(self, mock_getaddrinfo, message):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        recorder: dict = {}

        with patch("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(recorder)):
            result = await svc._send_discord(message)

        assert result["success"] is True
        assert recorder["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.smtplib.SMTP")
    @pytest.mark.asyncio
    async def test_email_requires_tls_for_smtp_auth(self, mock_smtp, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )

        result = await svc._send_email(message)

        assert result["success"] is False
        assert "Refusing SMTP authentication without TLS" in result["error"]
        mock_smtp.assert_not_called()

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    @pytest.mark.asyncio
    async def test_email_starttls_uses_verified_ssl_context(
        self, mock_smtp, mock_create_context, message
    ):
        tls_context = MagicMock()
        mock_create_context.return_value = tls_context
        server = MagicMock()
        mock_smtp.return_value = server

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )

        result = await svc._send_email(message)

        assert result["success"] is True
        server.starttls.assert_called_once_with(context=tls_context)
