"""Security tests for notification transport and config handling."""

import asyncio
import json
import ssl
from unittest.mock import Mock, patch

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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationConfigSecurity:
    """Validate persisted notification config does not include secret material."""

    def test_save_config_redacts_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer token-secret"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_secret" not in saved["sms"]


class _MockPostContext:
    def __init__(self):
        self.status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _MockClientSession:
    post_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        self.post_calls.append({"args": args, "kwargs": kwargs})
        return _MockPostContext()


class TestNotificationTransportSecurity:
    """Validate notification transports avoid credential and SSRF downgrade paths."""

    def setup_method(self):
        _MockClientSession.post_calls = []

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _MockClientSession)
    def test_slack_disables_redirects(self, getaddrinfo, message):
        getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _MockClientSession.post_calls[-1]["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _MockClientSession)
    def test_discord_disables_redirects(self, getaddrinfo, message):
        getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert _MockClientSession.post_calls[-1]["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.socket.getaddrinfo")
    @patch("core.notification_service.aiohttp.ClientSession", _MockClientSession)
    def test_webhook_disables_redirects(self, getaddrinfo, message):
        getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _MockClientSession.post_calls[-1]["kwargs"]["allow_redirects"] is False

    @patch("core.notification_service.smtplib.SMTP")
    def test_email_rejects_plaintext_smtp_auth(self, smtp_cls, message):
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

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        smtp_cls.return_value.login.assert_not_called()

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    def test_email_starttls_uses_verified_context(self, smtp_cls, create_default_context, message):
        context = Mock(spec=ssl.SSLContext)
        create_default_context.return_value = context
        smtp = Mock()
        smtp_cls.return_value = smtp
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

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp.starttls.assert_called_once_with(context=context)
