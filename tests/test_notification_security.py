"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

import pytest
from aiohttp import ClientTimeout

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


class _FakeWebhookResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def text(self):
        return ""


class _FakeWebhookSession:
    def __init__(self, calls):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def post(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return _FakeWebhookResponse()


class TestNotificationTransportSecurity:
    """Validate notification transport hardening."""

    def _message(self):
        return NotificationMessage(
            title="Security test",
            content="Test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/OKEN"
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeWebhookSession(calls),
        )

        result = asyncio.run(svc._send_slack(self._message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeWebhookSession(calls),
        )

        result = asyncio.run(svc._send_discord(self._message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        calls = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeWebhookSession(calls),
        )

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert calls[0]["kwargs"]["allow_redirects"] is False
        assert isinstance(calls[0]["kwargs"]["timeout"], ClientTimeout)

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        class FakeSMTP:
            starttls_context = None
            logged_in = False

            def __init__(self, *_args):
                pass

            def starttls(self, *, context=None):
                self.starttls_context = context

            def login(self, *_args):
                self.logged_in = True

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        fake_smtp = FakeSMTP()
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP", lambda *_args: fake_smtp
        )
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert isinstance(fake_smtp.starttls_context, ssl.SSLContext)
        assert fake_smtp.starttls_context.check_hostname is True
        assert fake_smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert fake_smtp.logged_in is True

    def test_smtp_auth_requires_tls(self, monkeypatch):
        def fail_if_called(*_args):
            raise AssertionError("SMTP should not be opened before TLS auth validation")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fail_if_called)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
