"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="hello",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportHardening:
    """Outbound webhook posts must not follow redirects to internal hosts."""

    def test_post_json_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        captured: dict = {}

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResponse()

        with patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()):
            result = asyncio.run(
                svc._post_json_no_redirect("https://example.com/hook", {"ok": True})
            )

        assert captured["kwargs"]["allow_redirects"] is False
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]


class TestSmtpTransportHardening:
    """SMTP authentication must use verified TLS."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        fake_server = MagicMock()
        captured_context = {}

        def starttls(*, context=None):
            captured_context["context"] = context

        fake_server.starttls.side_effect = starttls

        with patch("core.notification_service.smtplib.SMTP", return_value=fake_server):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = captured_context["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        fake_server.login.assert_called_once()
