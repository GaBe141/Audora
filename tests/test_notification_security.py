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
            svc._validate_webhook_url("https://user:token@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200, body: str = "ok") -> None:
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResponse | None = None) -> None:
        self.response = response or _FakeResponse()
        self.post_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, **kwargs):
        self.post_calls.append({"url": url, **kwargs})
        return self.response


def _sample_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="Body",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        fake_session = _FakeSession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"),
            patch("aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_slack(_sample_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert fake_session.post_calls[0]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        fake_session = _FakeSession(_FakeResponse(status=204))
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/discord"
            ),
            patch("aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_discord(_sample_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert fake_session.post_calls[0]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        fake_session = _FakeSession(_FakeResponse(status=302, body="redirect"))
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/custom"
            ),
            patch("aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]
        assert fake_session.post_calls[0]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS and must not authenticate in plaintext."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
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
        mock_server = MagicMock()
        with patch("smtplib.SMTP", return_value=mock_server) as mock_smtp:
            result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        mock_smtp.assert_called_once()
        starttls_kwargs = mock_server.starttls.call_args.kwargs
        assert isinstance(starttls_kwargs.get("context"), ssl.SSLContext)
        assert starttls_kwargs["context"].check_hostname is True
        mock_server.login.assert_called_once_with("user", "secret")
