"""Security tests for notification webhook URL validation."""

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
        with pytest.raises(ValueError, match="credential"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_strips_crlf_from_headers(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Hello\r\nBcc: evil@example.com") == "HelloBcc: evil@example.com"

    def test_rejects_attachments_outside_allowlist(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("nope")
        assert svc._is_allowed_attachment(str(secret)) is False


class TestNotificationTransportHardening:
    """SMTP and webhook transports must not leak credentials or follow redirects."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(self._message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(self._message()))
        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"] = {
            "url": "https://example.com/hook",
            "headers": {"Content-Type": "application/json"},
            "timeout": 5,
        }
        captured: dict = {}

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                captured.update(kwargs)
                captured["url"] = url
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(self._message()))
        assert result["success"] is True
        assert captured.get("allow_redirects") is False

    def test_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"] = {
            "url": "https://example.com/hook",
            "headers": {"Content-Type": "application/json"},
            "timeout": 5,
        }

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(self._message()))
        assert result["success"] is False
        assert "Redirect" in result["error"]
