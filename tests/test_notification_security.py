"""Security tests for notification transport hardening."""

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


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self) -> str:
        return ""


class _FakeClientSession:
    """Simple async session stub that captures POST kwargs."""

    def __init__(self, capture: dict[str, object]):
        self._capture = capture

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, _url, **kwargs):
        self._capture["allow_redirects"] = kwargs.get("allow_redirects")
        return _FakeResponse(status=200)


class TestOutboundTransportHardening:
    """Validate outbound transport protections against SSRF/MITM bypasses."""

    def test_custom_webhook_disables_http_redirects(self, monkeypatch):
        capture: dict[str, object] = {}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(capture),
        )

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert capture["allow_redirects"] is False

    def test_slack_disables_http_redirects(self, monkeypatch):
        capture: dict[str, object] = {}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(capture),
        )

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/services/abc"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        result = asyncio.run(svc._send_slack(msg))

        assert result["success"] is True
        assert capture["allow_redirects"] is False

    def test_discord_disables_http_redirects(self, monkeypatch):
        capture: dict[str, object] = {}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(capture),
        )

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/2"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        result = asyncio.run(svc._send_discord(msg))

        assert result["success"] is True
        assert capture["allow_redirects"] is False

    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured_context = {"value": None}

        class _FakeSMTP:
            def __init__(self, _host, _port):
                pass

            def starttls(self, context=None):
                captured_context["value"] = context

            def login(self, _username, _password):
                return None

            def send_message(self, _msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "pass"
        svc.config["email"]["recipients"] = ["user@example.com"]
        svc.config["email"]["use_tls"] = True

        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert isinstance(captured_context["value"], ssl.SSLContext)
        assert captured_context["value"].check_hostname is True
