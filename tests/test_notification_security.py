"""Security tests for notification webhook URL validation."""

import asyncio
import json
import ssl
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class _FakeResponse:
    def __init__(self, status: int, body: str = ""):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return self._body


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        self.post_kwargs = kwargs
        return self.response


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


class TestWebhookTransportSecurity:
    """Validate redirect and DNS-rebinding protections for webhook sends."""

    def test_slack_send_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        svc._resolve_webhook_url = MagicMock(
            return_value=("https://hooks.example.com/slack", "hooks.example.com", ("203.0.113.10",))
        )
        fake_session = _FakeSession(_FakeResponse(302, "redirect"))
        svc._webhook_session = MagicMock(return_value=fake_session)
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert fake_session.post_kwargs["allow_redirects"] is False
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_custom_webhook_send_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://webhook.example.com/event"
        svc._resolve_webhook_url = MagicMock(
            return_value=(
                "https://webhook.example.com/event",
                "webhook.example.com",
                ("203.0.113.20",),
            )
        )
        fake_session = _FakeSession(_FakeResponse(204))
        svc._webhook_session = MagicMock(return_value=fake_session)
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert fake_session.post_kwargs["allow_redirects"] is False
        assert result["success"] is True


class TestSmtpTransportSecurity:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_rejects_plaintext_smtp_auth(self):
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
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP") as smtp:
            result = asyncio.run(svc._send_email(message))

        smtp.assert_not_called()
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
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
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()
        smtp_context = MagicMock()
        smtp_context.__enter__.return_value = server

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_context):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        tls_context = server.starttls.call_args.kwargs["context"]
        assert isinstance(tls_context, ssl.SSLContext)
        assert tls_context.check_hostname is True
        assert tls_context.verify_mode == ssl.CERT_REQUIRED


class TestConfigPersistenceSecurity:
    """Saved notification config should not persist plaintext secrets."""

    def test_save_config_omits_sensitive_values(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/secret"
        svc.config["discord"]["webhook_url"] = "https://discord.example.com/secret"
        svc.config["webhook"]["url"] = "https://webhook.example.com/secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        svc.config["sms"]["api_key"] = "sms-key"
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "webhook_url" not in saved["slack"]
        assert "webhook_url" not in saved["discord"]
        assert "url" not in saved["webhook"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
