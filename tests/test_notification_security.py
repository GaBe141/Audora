"""Security tests for notification transport hardening."""

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


class _MockResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _MockSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, _url, **kwargs):
        type(self).last_post_kwargs = kwargs
        return _MockResponse()


class TestNotificationTransportSecurity:
    """Validate secure transport behavior for notification channels."""

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Security test",
            content="transport hardening",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    @pytest.mark.parametrize(
        ("channel_name", "config_key", "send_method"),
        [
            ("slack", "slack", "_send_slack"),
            ("discord", "discord", "_send_discord"),
            ("webhook", "webhook", "_send_webhook"),
        ],
    )
    def test_webhook_channels_disable_redirects(
        self, monkeypatch, message, channel_name, config_key, send_method
    ):
        svc = EnhancedNotificationService()
        svc.config[config_key]["webhook_url" if channel_name != "webhook" else "url"] = (
            "https://hooks.example.com/path"
        )
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_kwargs: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _MockSession)

        result = asyncio.run(getattr(svc, send_method)(message))

        assert result["success"] is True
        assert _MockSession.last_post_kwargs["allow_redirects"] is False

    def test_email_refuses_plaintext_smtp_auth(self, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )
        smtp = MagicMock()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", MagicMock(return_value=smtp))

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        starttls_context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(starttls_context, ssl.SSLContext)
        assert starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert starttls_context.check_hostname is True
