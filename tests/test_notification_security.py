"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import patch

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

    def test_rejects_embedded_userinfo(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportSecurity:
    """Security tests for transport-layer protections."""

    def test_smtp_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "from_address": "from@example.com",
                "recipients": ["to@example.com"],
                "use_tls": True,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        class FakeSMTP:
            captured_context = None

            def __init__(self, *_args, **_kwargs):
                self.started_tls = False

            def starttls(self, context=None):
                self.started_tls = True
                FakeSMTP.captured_context = context

            def login(self, *_args, **_kwargs):
                return None

            def send_message(self, *_args, **_kwargs):
                return None

            def quit(self):
                return None

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert FakeSMTP.captured_context is not None
        assert getattr(FakeSMTP.captured_context, "check_hostname", False) is True

    def test_webhook_redirect_is_blocked(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class FakeResponse:
            status = 302

            async def text(self):
                return ""

        class _PostContext:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeClientSession:
            last_allow_redirects = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                FakeClientSession.last_allow_redirects = kwargs.get("allow_redirects")
                return _PostContext()

        msg = NotificationMessage(
            title="Redirect test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch("core.notification_service.aiohttp.ClientSession", FakeClientSession),
            patch.object(
                EnhancedNotificationService,
                "_validate_webhook_url",
                return_value="https://example.com/hook",
            ),
        ):
            result = asyncio.run(svc._send_webhook(msg))

        assert FakeClientSession.last_allow_redirects is False
        assert result["success"] is False
        assert "redirect blocked" in result["error"].lower()
