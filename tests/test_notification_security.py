"""Security tests for notification transport validation."""

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
    def __init__(self, status: int, body: str = ""):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._body


class _FakeSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, _url, **kwargs):
        type(self).last_post_kwargs = kwargs
        return _FakeResponse(302, "redirect")


@pytest.mark.asyncio
class TestWebhookTransportHardening:
    """Validate redirect-chain SSRF protections on outbound webhook sends."""

    @pytest.fixture(autouse=True)
    def _mock_public_dns(self):
        with patch("core.notification_service.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 443)),
            ]
            yield

    async def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with patch("core.notification_service.aiohttp.ClientSession", _FakeSession):
            result = await svc._send_webhook(message)

        assert result["success"] is False
        assert "Redirect" in result["error"]
        assert _FakeSession.last_post_kwargs["allow_redirects"] is False


class TestEmailTransportHardening:
    """Validate SMTP credential transport protections."""

    def test_starttls_uses_validating_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "",
                "password": "",
                "use_tls": True,
            }
        )
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        smtp.login.assert_not_called()


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="Body",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.EMAIL],
    )
