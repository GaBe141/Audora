"""Security tests for notification transport hardening."""

import asyncio
import ssl

import aiohttp
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


class TestWebhookDeliverySecurity:
    """Validate outbound webhook calls do not follow redirects after URL checks."""

    @pytest.mark.parametrize(
        ("method_name", "config_key", "url_key"),
        [
            ("_send_slack", "slack", "webhook_url"),
            ("_send_discord", "discord", "webhook_url"),
            ("_send_webhook", "webhook", "url"),
        ],
    )
    def test_webhook_senders_disable_redirects(self, monkeypatch, method_name, config_key, url_key):
        svc = EnhancedNotificationService()
        svc.config[config_key][url_key] = "https://example.com/webhook"

        captured_kwargs = {}

        class MockResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class MockSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured_kwargs.update(kwargs)
                return MockResponse()

        monkeypatch.setattr(aiohttp, "ClientSession", MockSession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)

        message = NotificationMessage(
            title="Security test",
            content="Do not follow redirects",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(getattr(svc, method_name)(message))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_refuses_smtp_credentials_without_tls(self):
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
            title="Security test",
            content="No plaintext credentials",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_smtp_starttls_uses_default_ssl_context(self, monkeypatch):
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
        created_context = ssl.create_default_context()
        observed = {}

        class MockSMTP:
            def __init__(self, server, port):
                observed["server"] = server
                observed["port"] = port

            def starttls(self, *, context):
                observed["context"] = context

            def login(self, username, password):
                observed["login"] = (username, password)

            def send_message(self, message):
                observed["sent"] = True

            def quit(self):
                observed["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", MockSMTP)
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: created_context,
        )

        message = NotificationMessage(
            title="Security test",
            content="Verified TLS",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert observed["context"] is created_context
        assert observed["login"] == ("user", "secret")
        assert observed["sent"] is True
        assert observed["quit"] is True
