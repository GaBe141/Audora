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


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeClientSession:
    calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return _FakeResponse()


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="Test content",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.CONSOLE],
    )


def _mock_public_dns(monkeypatch):
    monkeypatch.setattr(
        "core.notification_service.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookRedirectProtection:
    """Outbound webhook transports must not follow redirects after validation."""

    def test_slack_send_disables_redirects(self, monkeypatch):
        _mock_public_dns(monkeypatch)
        _FakeClientSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(_message()))

        assert result["success"] is True
        assert _FakeClientSession.calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self, monkeypatch):
        _mock_public_dns(monkeypatch)
        _FakeClientSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(_message()))

        assert result["success"] is True
        assert _FakeClientSession.calls[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        _mock_public_dns(monkeypatch)
        _FakeClientSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom"

        result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert _FakeClientSession.calls[0]["kwargs"]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP credentials must only be sent after verified STARTTLS."""

    def test_rejects_smtp_auth_without_tls(self):
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

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, message):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        assert captured["login"] == ("user", "secret")
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
