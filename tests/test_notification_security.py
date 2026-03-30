"""Security tests for notification webhook URL validation and transport hardening."""

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


class TestWebhookRedirectHardening:
    """Ensure outbound webhook clients do not follow redirects."""

    def _patch_client_session(self, monkeypatch: pytest.MonkeyPatch, response_status: int = 200):
        captured: dict[str, object] = {}

        class FakeResponse:
            def __init__(self, status: int):
                self.status = status

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["args"] = args
                captured["kwargs"] = kwargs
                return FakeResponse(response_status)

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda *a, **k: FakeSession()
        )
        return captured

    def test_send_webhook_disables_redirects(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_client_session(monkeypatch)

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_send_slack_disables_redirects(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_client_session(monkeypatch)

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_send_discord_disables_redirects(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_client_session(monkeypatch, response_status=204)

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False


class TestEmailTlsHardening:
    """Ensure SMTP STARTTLS uses certificate-validating context."""

    def test_send_email_uses_default_tls_context(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "from_address": "alerts@example.com",
                "recipients": ["ops@example.com"],
                "use_tls": True,
            }
        )

        captured: dict[str, object] = {}

        class FakeSmtp:
            def __init__(self, host: str, port: int, timeout: int | None = None):
                captured["host"] = host
                captured["port"] = port
                captured["timeout"] = timeout
                self.starttls_context = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def ehlo(self):
                return None

            def starttls(self, context=None):
                self.starttls_context = context
                captured["context"] = context
                return None

            def login(self, username: str, password: str):
                captured["username"] = username
                captured["password"] = password
                return None

            def send_message(self, msg):
                captured["subject"] = msg["Subject"]
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSmtp)

        message = NotificationMessage(
            title="test email",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
