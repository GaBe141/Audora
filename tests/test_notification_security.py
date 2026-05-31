"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

import pytest

import core.notification_service as notification_service
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


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self, calls, status: int = 200):
        self.calls = calls
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return _FakeResponse(self.status)


class TestNotificationTransportSecurity:
    """Validate transport security for outbound notification channels."""

    def _message(self):
        return NotificationMessage(
            title="Security test",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.HIGH,
            channels=[],
        )

    def test_smtp_starttls_uses_verified_ssl_context(self):
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
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_smtp_refuses_plaintext_authentication(self):
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
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp.login.assert_not_called()

    def test_email_html_escapes_message_content(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )
        smtp = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            asyncio.run(svc._send_email(self._message()))

        message = smtp.send_message.call_args.args[0]
        html_part = message.get_payload()[1].get_payload()
        assert "&lt;script&gt;" in html_part
        assert "<script>" not in html_part

    def test_webhook_channels_disable_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/webhook"
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)

        calls = []
        monkeypatch.setattr(
            notification_service.aiohttp,
            "ClientSession",
            lambda: _FakeSession(calls),
        )

        message = self._message()
        asyncio.run(svc._send_slack(message))
        asyncio.run(svc._send_discord(message))
        asyncio.run(svc._send_webhook(message))

        assert len(calls) == 3
        assert all(call["kwargs"]["allow_redirects"] is False for call in calls)
