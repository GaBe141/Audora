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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 302) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return "redirect"


class _FakeSession:
    captured_kwargs: dict

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *_args, **kwargs):
        type(self).captured_kwargs = kwargs
        return _FakeResponse()


class TestNotificationTransportSecurity:
    """Validate outbound transports avoid credential and SSRF bypasses."""

    @pytest.mark.asyncio
    async def test_slack_webhook_disables_redirects(self, monkeypatch):
        monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))])
        monkeypatch.setattr("aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = await svc._send_slack(message)

        assert result["success"] is False
        assert _FakeSession.captured_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_discord_webhook_disables_redirects(self, monkeypatch):
        monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))])
        monkeypatch.setattr("aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = await svc._send_discord(message)

        assert result["success"] is False
        assert _FakeSession.captured_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_custom_webhook_disables_redirects(self, monkeypatch):
        monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))])
        monkeypatch.setattr("aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = await svc._send_webhook(message)

        assert result["success"] is False
        assert _FakeSession.captured_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_smtp_starttls_uses_validating_ssl_context(self):
        smtp = MagicMock()
        smtp_cls = MagicMock(return_value=smtp)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "",
                "password": "",
                "use_tls": True,
            }
        )

        with patch("smtplib.SMTP", smtp_cls):
            result = await svc._send_email(
                NotificationMessage(
                    title="test",
                    content="body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    @pytest.mark.asyncio
    async def test_smtp_auth_requires_tls(self):
        smtp = MagicMock()
        smtp_cls = MagicMock(return_value=smtp)
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

        with patch("smtplib.SMTP", smtp_cls):
            result = await svc._send_email(
                NotificationMessage(
                    title="test",
                    content="body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        smtp.login.assert_not_called()
