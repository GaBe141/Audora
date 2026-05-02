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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _MockResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "mock response"


class _MockSession:
    calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _MockResponse()


class TestNotificationTransportHardening:
    """Validate redirect and SMTP credential protections."""

    @pytest.fixture(autouse=True)
    def _mock_dns(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )

    @pytest.mark.parametrize(
        ("channel", "config_key", "send_method"),
        [
            (NotificationChannel.SLACK, "slack", "_send_slack"),
            (NotificationChannel.DISCORD, "discord", "_send_discord"),
            (NotificationChannel.WEBHOOK, "webhook", "_send_webhook"),
        ],
    )
    def test_webhook_channels_disable_redirects(self, monkeypatch, channel, config_key, send_method):
        _MockSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _MockSession)
        svc = EnhancedNotificationService()
        if config_key == "webhook":
            svc.config[config_key]["url"] = "https://example.com/webhook"
        else:
            svc.config[config_key]["webhook_url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Security Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

        result = asyncio.run(getattr(svc, send_method)(message))

        assert result["success"] is True
        assert _MockSession.calls
        assert _MockSession.calls[0][1]["allow_redirects"] is False

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_smtp_starttls_uses_validating_context(self, monkeypatch):
        contexts = []

        class MockSmtp:
            def __init__(self, *args, **kwargs):
                self.started_context = None

            def starttls(self, *, context):
                self.started_context = context
                contexts.append(context)

            def send_message(self, msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", MockSmtp)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "",
                "password": "",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Security Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert contexts
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED
