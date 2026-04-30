"""Security tests for notification delivery hardening."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

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


class TestNotificationSecretHandling:
    """Ensure notification configuration does not persist credentials."""

    def test_save_config_redacts_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"
        svc.config["webhook"]["headers"]["X-API-Key"] = "api-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "X-API-Key" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]


class TestNotificationTransportSecurity:
    """Validate outbound notification transport protections."""

    def test_template_names_must_be_known(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Test",
            content="Fallback content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.CONSOLE],
            template_vars={"template": "missing_template"},
        )

        with pytest.raises(ValueError, match="Unknown notification template"):
            svc._render_template(message)

    @pytest.mark.asyncio
    async def test_webhook_redirects_are_disabled(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        response = AsyncMock()
        response.status = 200
        response.__aenter__.return_value = response
        response.__aexit__.return_value = None

        session = AsyncMock()
        session.__aenter__.return_value = session
        session.__aexit__.return_value = None
        session.post.return_value = response

        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch("core.notification_service.socket.getaddrinfo") as getaddrinfo,
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            getaddrinfo.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
            result = await svc._send_webhook(message)

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result == {"success": False, "error": "Refusing SMTP authentication without TLS"}

    @pytest.mark.asyncio
    async def test_smtp_starttls_uses_verified_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = None
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp),
            patch("core.notification_service.ssl.create_default_context") as create_context,
        ):
            context = MagicMock()
            create_context.return_value = context
            result = await svc._send_email(message)

        assert result["success"] is True
        smtp.starttls.assert_called_once_with(context=context)
