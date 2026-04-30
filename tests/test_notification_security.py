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
    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeClientSession:
    last_post_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        _FakeClientSession.last_post_kwargs = kwargs
        return _FakeResponse()


@pytest.mark.asyncio
class TestWebhookRedirectHardening:
    """Ensure validated webhooks cannot follow redirects to internal hosts."""

    @pytest.fixture(autouse=True)
    def _public_dns(self):
        with patch("core.notification_service.socket.getaddrinfo") as getaddrinfo:
            getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 443)),
            ]
            yield

    async def test_slack_disables_redirects(self, monkeypatch):
        _FakeClientSession.last_post_kwargs = None
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )
        result = await svc._send_slack(message)

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False

    async def test_discord_disables_redirects(self, monkeypatch):
        _FakeClientSession.last_post_kwargs = None
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )
        result = await svc._send_discord(message)

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False

    async def test_custom_webhook_disables_redirects(self, monkeypatch):
        _FakeClientSession.last_post_kwargs = None
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = await svc._send_webhook(message)

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False


@pytest.mark.asyncio
class TestSmtpTransportSecurity:
    """Protect SMTP credentials with verified TLS."""

    async def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    async def test_starttls_uses_default_ssl_context(self):
        smtp = MagicMock()
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        tls_context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(tls_context, ssl.SSLContext)
        assert tls_context.check_hostname is True
