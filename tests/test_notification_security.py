"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

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


class TestNotificationTransportSecurity:
    """Validate secure transport settings for outbound notification channels."""

    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="Transport test",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    def _patch_aiohttp_session(self, monkeypatch, captured_posts):
        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured_posts.append({"args": args, "kwargs": kwargs})
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

    def test_webhook_channels_disable_redirects(self, monkeypatch):
        captured_posts = []
        self._patch_aiohttp_session(monkeypatch, captured_posts)

        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_kwargs: url)
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        svc.config["webhook"]["url"] = "https://example.com/custom"

        asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))
        asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))
        asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert len(captured_posts) == 3
        assert all(post["kwargs"]["allow_redirects"] is False for post in captured_posts)

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, *, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["username"] = username
                captured["password"] = password

            def send_message(self, message):
                captured["subject"] = message["Subject"]

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "secret",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert captured["context"].check_hostname is True
        assert captured["username"] == "user"
        assert captured["quit"] is True

    def test_smtp_credentials_require_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "without TLS" in result["error"]
