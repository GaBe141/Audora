"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class _FakeRedirectResponse:
    status = 302

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def text(self):
        return "redirect"


class _FakeSession:
    def __init__(self, calls):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def post(self, *args, **kwargs):
        self.calls.append(kwargs)
        return _FakeRedirectResponse()


class TestWebhookRedirectProtection:
    """Validated webhooks must not be allowed to redirect to private targets."""

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        result = asyncio.run(svc._send_slack(message))

        assert calls[0]["allow_redirects"] is False
        assert result["success"] is False
        assert "redirects" in result["error"]

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        result = asyncio.run(svc._send_discord(message))

        assert calls[0]["allow_redirects"] is False
        assert result["success"] is False
        assert "redirects" in result["error"]

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc.config["webhook"]["url"] = "https://example.com/custom"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert calls[0]["allow_redirects"] is False
        assert result["success"] is False
        assert "redirects" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP credentials must only be sent over verified TLS."""

    def _message(self):
        return NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        smtp = MagicMock()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *args: smtp)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        smtp.login.assert_called_once_with("user", "secret")
