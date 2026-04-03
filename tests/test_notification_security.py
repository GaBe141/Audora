"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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


class _DummyResponse:
    """Minimal async HTTP response context manager for transport tests."""

    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _DummySession:
    """Capture outgoing POST kwargs while emulating aiohttp session API."""

    def __init__(self, call_log: list[dict]):
        self._call_log = call_log

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self._call_log.append({"url": url, **kwargs})
        return _DummyResponse()


class TestOutboundTransportHardening:
    """Validate redirect and TLS hardening for outbound notifications."""

    def test_slack_disables_http_redirects(self, monkeypatch):
        call_log: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/path"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(call_log),
        )
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="Slack",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )

        result = asyncio.run(svc._send_slack(msg))
        assert result["success"] is True
        assert call_log
        assert call_log[0]["allow_redirects"] is False

    def test_discord_disables_http_redirects(self, monkeypatch):
        call_log: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(call_log),
        )
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="Discord",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )

        result = asyncio.run(svc._send_discord(msg))
        assert result["success"] is True
        assert call_log
        assert call_log[0]["allow_redirects"] is False

    def test_custom_webhook_disables_http_redirects(self, monkeypatch):
        call_log: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://webhook.example/ingest"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(call_log),
        )
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="Webhook",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )

        result = asyncio.run(svc._send_webhook(msg))
        assert result["success"] is True
        assert call_log
        assert call_log[0]["allow_redirects"] is False

    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured: dict[str, object] = {}

        class _DummySMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, *, context=None):
                captured["tls_context"] = context

            def login(self, username, password):
                captured["username"] = username
                captured["password"] = password

            def send_message(self, _msg):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "audora@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }

        msg = NotificationMessage(
            title="Email",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )
        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert isinstance(captured.get("tls_context"), ssl.SSLContext)
