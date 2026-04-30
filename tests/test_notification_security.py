"""Security tests for notification transport and secret handling."""

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


def _message_for(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="Transport check",
        priority=NotificationPriority.HIGH,
        channels=[channel],
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


class TestNotificationSecretPersistence:
    """Ensure saved notification config omits reusable credentials."""

    def test_save_config_redacts_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]


class TestNotificationTransportSecurity:
    """Regression tests for outbound notification transport safeguards."""

    @pytest.mark.asyncio
    async def test_email_refuses_plaintext_auth(self):
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

        with patch("core.notification_service.smtplib.SMTP") as smtp:
            result = await svc._send_email(_message_for(NotificationChannel.EMAIL))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp.assert_not_called()

    @pytest.mark.asyncio
    async def test_email_uses_verified_starttls_context(self):
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
        smtp_instance = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance):
            result = await svc._send_email(_message_for(NotificationChannel.EMAIL))

        assert result["success"] is True
        starttls_context = smtp_instance.starttls.call_args.kwargs["context"]
        assert isinstance(starttls_context, ssl.SSLContext)
        assert starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert starttls_context.check_hostname is True

    @pytest.mark.parametrize(
        ("channel", "config_key", "url_key"),
        [
            (NotificationChannel.SLACK, "slack", "webhook_url"),
            (NotificationChannel.DISCORD, "discord", "webhook_url"),
            (NotificationChannel.WEBHOOK, "webhook", "url"),
        ],
    )
    @pytest.mark.asyncio
    async def test_webhook_posts_disable_redirects(self, channel, config_key, url_key):
        svc = EnhancedNotificationService()
        svc.config[config_key][url_key] = "https://hooks.example.com/notify"

        captured_kwargs = {}

        class FakeResponse:
            status = 204 if channel is NotificationChannel.DISCORD else 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            handler = {
                NotificationChannel.SLACK: svc._send_slack,
                NotificationChannel.DISCORD: svc._send_discord,
                NotificationChannel.WEBHOOK: svc._send_webhook,
            }[channel]
            result = await handler(_message_for(channel))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False
