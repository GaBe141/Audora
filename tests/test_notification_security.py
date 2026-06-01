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


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self, captured):
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url, **kwargs):
        self.captured.append({"url": url, "kwargs": kwargs})
        return _FakeResponse()


def _public_dns(*_args, **_kwargs):
    return [(None, None, None, None, ("93.184.216.34", 443))]


def _message(channel):
    return NotificationMessage(
        title="Security test",
        content="transport check",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class TestNotificationTransportSecurity:
    """Validate notification transports do not bypass URL validation."""

    def test_slack_disables_redirects(self, monkeypatch):
        captured = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _public_dns)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(captured),
        )

        result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert captured[0]["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        captured = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _public_dns)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(captured),
        )

        result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert captured[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _public_dns)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(captured),
        )

        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert captured[0]["kwargs"]["allow_redirects"] is False

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["recipient@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_smtp_starttls_uses_validating_context(self, monkeypatch):
        contexts = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context):
                contexts.append(context)

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "",
                "password": "",
                "recipients": ["recipient@example.com"],
                "use_tls": True,
            }
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED
