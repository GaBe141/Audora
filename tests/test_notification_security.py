"""Security tests for notification webhook URL validation."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self) -> str:
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _FakeSession:
    def __init__(self):
        self.post_kwargs: dict | None = None

    def post(self, _url, **kwargs):
        self.post_kwargs = kwargs
        return _FakeResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


def _public_dns():
    return patch(
        "core.notification_service.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("8.8.8.8", 443))],
    )


class TestWebhookTransportHardening:
    """Ensure outbound notification channels do not follow redirects."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        session = _FakeSession()
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        with _public_dns(), patch(
            "core.notification_service.aiohttp.ClientSession", return_value=session
        ):
            result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        session = _FakeSession()
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        with _public_dns(), patch(
            "core.notification_service.aiohttp.ClientSession", return_value=session
        ):
            result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        session = _FakeSession()
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        with _public_dns(), patch(
            "core.notification_service.aiohttp.ClientSession", return_value=session
        ):
            result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False


class TestSmtpTransportSecurity:
    """Validate SMTP TLS requirements and certificate verification."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        smtp.starttls.assert_called_once()
        context = smtp.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
