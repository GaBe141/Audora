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


class FakeWebhookResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "ok"


class FakeWebhookSession:
    def __init__(self, calls: list[dict]):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return FakeWebhookResponse(status=200)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="transport hardening",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.WEBHOOK],
    )


class TestWebhookTransportHardening:
    """Validate outbound webhook calls do not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: FakeWebhookSession(calls)
        )

        result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: FakeWebhookSession(calls)
        )

        result = asyncio.run(svc._send_slack(_message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: FakeWebhookSession(calls)
        )

        result = asyncio.run(svc._send_discord(_message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False


class FakeSmtpServer:
    def __init__(self, *args, **kwargs):
        self.starttls_context = None
        self.logged_in = False

    def starttls(self, *, context=None):
        self.starttls_context = context

    def login(self, username, password):
        self.logged_in = True

    def send_message(self, message):
        return None

    def quit(self):
        return None


class TestEmailTransportHardening:
    """Validate SMTP credential transport protections."""

    def test_smtp_auth_requires_tls(self, monkeypatch):
        smtp_instances = []
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
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: smtp_instances.append(FakeSmtpServer()) or smtp_instances[-1],
        )

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        assert smtp_instances == []

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        smtp_instances = []
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: smtp_instances.append(FakeSmtpServer()) or smtp_instances[-1],
        )

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = smtp_instances[0].starttls_context
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert smtp_instances[0].logged_in is True
