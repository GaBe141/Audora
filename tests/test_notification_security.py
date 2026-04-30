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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _AsyncResponse:
    def __init__(self, status: int):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return "redirect"


class _RecordingSession:
    last_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url, **kwargs):
        type(self).last_kwargs = kwargs
        return _AsyncResponse(302)


class TestNotificationTransports:
    """Verify transport settings that prevent credential exposure and SSRF bypasses."""

    def test_email_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "use_tls": False,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
            }
        )
        message = NotificationMessage(
            title="title",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = svc._send_email(message)

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_email_starttls_uses_verified_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "use_tls": True,
                "username": "",
                "password": "",
                "recipients": ["alerts@example.com"],
            }
        )
        server = MagicMock()
        message = NotificationMessage(
            title="title",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = svc._send_email(message)

        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    @pytest.mark.asyncio
    async def test_webhook_redirects_are_not_followed(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _RecordingSession)
        message = NotificationMessage(
            title="title",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = await svc._send_webhook(message)

        assert result["success"] is False
        assert _RecordingSession.last_kwargs["allow_redirects"] is False
