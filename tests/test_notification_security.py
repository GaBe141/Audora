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
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "ok"


class _FakeSession:
    def __init__(self, calls, status=200):
        self.calls = calls
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return _FakeResponse(self.status)


class _FakeSMTP:
    instances = []

    def __init__(self, smtp_server, port):
        self.smtp_server = smtp_server
        self.port = port
        self.starttls_context = None
        self.logged_in = False
        self.sent = False
        self.quit_called = False
        self.__class__.instances.append(self)

    def starttls(self, context=None):
        self.starttls_context = context

    def login(self, username, password):
        self.logged_in = True

    def send_message(self, msg):
        self.sent = True

    def quit(self):
        self.quit_called = True


def _message(channels=None):
    return NotificationMessage(
        title="Security test",
        content="Payload",
        priority=NotificationPriority.HIGH,
        channels=channels or [NotificationChannel.CONSOLE],
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
    """Validate outbound notification transport hardening."""

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/B/C"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_slack(_message([NotificationChannel.SLACK])))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls, status=204),
        )
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/token"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_discord(_message([NotificationChannel.DISCORD])))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_webhook(_message([NotificationChannel.WEBHOOK])))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_message([NotificationChannel.EMAIL])))

        assert result["success"] is True
        smtp = _FakeSMTP.instances[0]
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.logged_in is True

    def test_smtp_auth_requires_tls(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(_message([NotificationChannel.EMAIL])))

        assert result["success"] is False
        assert "SMTP authentication requires TLS" in result["error"]
        assert _FakeSMTP.instances == []
