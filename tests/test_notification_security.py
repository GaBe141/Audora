"""Security tests for notification transport hardening."""

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


class TestNotificationTransportSecurity:
    """Validate outbound notification transport protections."""

    @pytest.mark.parametrize(
        ("config_key", "method_name", "channel"),
        [
            ("slack", "_send_slack", NotificationChannel.SLACK),
            ("discord", "_send_discord", NotificationChannel.DISCORD),
            ("webhook", "_send_webhook", NotificationChannel.WEBHOOK),
        ],
    )
    @pytest.mark.asyncio
    async def test_webhook_sends_disable_redirects(self, config_key, method_name, channel):
        svc = EnhancedNotificationService()
        if config_key == "webhook":
            svc.config[config_key]["url"] = "https://example.com/webhook"
        else:
            svc.config[config_key]["webhook_url"] = "https://example.com/webhook"

        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

        class MockResponse:
            status = 200

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

        class MockSession:
            def post(self, *args, **kwargs):
                assert kwargs["allow_redirects"] is False
                return MockResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=MockSession()),
        ):
            result = await getattr(svc, method_name)(message)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_smtp_starttls_uses_verified_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "",
                "password": "",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch("core.notification_service.ssl.create_default_context") as create_context,
        ):
            result = await svc._send_email(message)

        assert result["success"] is True
        server.starttls.assert_called_once_with(context=create_context.return_value)

    @pytest.mark.asyncio
    async def test_smtp_refuses_auth_without_tls(self):
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
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = await svc._send_email(message)

        assert result["success"] is False
        assert "without TLS" in result["error"]
        server.login.assert_not_called()
