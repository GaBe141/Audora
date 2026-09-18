"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import patch

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

    def test_rejects_cgnat_shared_address_space(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_private_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.0.0.1]/webhook")


class _DummyResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _DummySession:
    def __init__(self, status: int = 200):
        self.status = status
        self.post_kwargs: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.post_kwargs.append(kwargs)
        return _DummyResponse(self.status)


def _sample_message(*channels: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="security-test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=list(channels),
    )


class TestWebhookTransportHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_slack_disables_redirects(self):
        session = _DummySession()
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://8.8.8.8/slack"
        with patch("core.notification_service.aiohttp.ClientSession", return_value=session):
            result = asyncio.run(svc._send_slack(_sample_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert session.post_kwargs[0]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        session = _DummySession(status=204)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://8.8.8.8/discord"
        with patch("core.notification_service.aiohttp.ClientSession", return_value=session):
            result = asyncio.run(svc._send_discord(_sample_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert session.post_kwargs[0]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        session = _DummySession(status=302)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://8.8.8.8/hook"
        with patch("core.notification_service.aiohttp.ClientSession", return_value=session):
            result = asyncio.run(svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post_kwargs[0]["allow_redirects"] is False


class TestSmtpTransportHardening:
    """SMTP must use verified TLS before transmitting credentials."""

    def test_refuses_plaintext_smtp_authentication(self):
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
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "tls" in result["error"].lower()

    def test_starttls_uses_verified_ssl_context(self):
        captured: dict[str, object] = {}

        class DummySMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, *, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                return {}

            def quit(self):
                captured["quit"] = True

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
        with patch("core.notification_service.smtplib.SMTP", DummySMTP):
            result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode != ssl.CERT_NONE
        assert context.check_hostname is True
