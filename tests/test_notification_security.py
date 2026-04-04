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

    def test_slack_request_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class _FakeResponse:
            status = 200

            async def text(self):
                return "ok"

        class _FakePostContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["kwargs"] = kwargs
                return _FakePostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"

        message = NotificationMessage(
            title="Security test",
            content="Verify redirect handling",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_discord_request_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class _FakeResponse:
            status = 204

            async def text(self):
                return "ok"

        class _FakePostContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["kwargs"] = kwargs
                return _FakePostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        message = NotificationMessage(
            title="Security test",
            content="Verify redirect handling",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_request_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class _FakeResponse:
            status = 200

            async def text(self):
                return "ok"

        class _FakePostContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["kwargs"] = kwargs
                return _FakePostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 10

        message = NotificationMessage(
            title="Security test",
            content="Verify redirect handling",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_email_uses_verified_tls_context_for_starttls(self, monkeypatch):
        captured: dict[str, object] = {}

        class _FakeSmtp:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, *, context):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, _message):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSmtp)

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "noreply@example.com",
            "recipients": ["alice@example.com"],
            "use_tls": True,
        }

        message = NotificationMessage(
            title="Security test",
            content="Verify TLS context",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert captured["context"].check_hostname is True
