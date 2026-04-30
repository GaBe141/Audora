"""Security tests for notification webhook URL validation."""

import json
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportSecurity:
    """Validate transport hardening for outbound notifications."""

    def test_smtp_uses_verified_tls_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["user@example.com"],
                "use_tls": True,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        context = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp),
            patch("core.notification_service.ssl.create_default_context", return_value=context),
        ):
            import asyncio

            result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        smtp.starttls.assert_called_once_with(context=context)
        smtp.login.assert_called_once_with("user", "pass")

    def test_smtp_rejects_credentials_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["user@example.com"],
                "use_tls": False,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        import asyncio

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_save_config_strips_persisted_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/secret"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/secret"
        svc.config["webhook"]["url"] = "https://example.com/hook"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        path = tmp_path / "notification_config.json"
        svc.save_config(str(path))

        saved = json.loads(path.read_text())
        assert "password" not in saved["email"]
        assert "webhook_url" not in saved["slack"]
        assert "webhook_url" not in saved["discord"]
        assert "url" not in saved["webhook"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]


class _FakeResponse:
    status = 200

    async def text(self):
        return ""


class _FakePostContext:
    def __init__(self, kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return _FakeResponse()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    last_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        type(self).last_kwargs = kwargs
        return _FakePostContext(kwargs)


class TestWebhookRedirectPolicy:
    """Ensure webhook requests cannot follow redirects to internal services."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", _FakeSession),
        ):
            import asyncio

            result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert _FakeSession.last_kwargs["allow_redirects"] is False
