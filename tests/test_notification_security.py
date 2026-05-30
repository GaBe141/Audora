"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock

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

    def test_rejects_embedded_credentials(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportSecurity:
    """Validate outbound notification transport hardening."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

    def test_smtp_starttls_uses_validating_ssl_context(self, monkeypatch):
        starttls_contexts = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context=None):
                starttls_contexts.append(context)

            def login(self, *_args, **_kwargs):
                pass

            def send_message(self, *_args, **_kwargs):
                pass

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert isinstance(starttls_contexts[0], ssl.SSLContext)
        assert starttls_contexts[0].check_hostname is True
        assert starttls_contexts[0].verify_mode == ssl.CERT_REQUIRED

    def test_smtp_auth_without_tls_is_rejected(self, monkeypatch):
        smtp_constructor = MagicMock()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", smtp_constructor)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp_constructor.assert_not_called()

    @pytest.mark.parametrize(
        ("channel_name", "send_method", "success_status"),
        [
            ("slack", "_send_slack", 200),
            ("discord", "_send_discord", 204),
            ("webhook", "_send_webhook", 200),
        ],
    )
    def test_webhook_channels_disable_redirects(
        self, monkeypatch, channel_name, send_method, success_status
    ):
        post_kwargs = []

        class FakeResponse:
            status = success_status

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, *_args, **kwargs):
                post_kwargs.append(kwargs)
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        if channel_name == "webhook":
            svc.config[channel_name]["url"] = "https://example.com/webhook"
        else:
            svc.config[channel_name]["webhook_url"] = "https://example.com/webhook"

        result = asyncio.run(getattr(svc, send_method)(self._message()))

        assert result["success"] is True
        assert post_kwargs[0]["allow_redirects"] is False
