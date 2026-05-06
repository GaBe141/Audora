"""Security tests for notification transport hardening."""

import asyncio
import ssl

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


class TestNotificationTransports:
    """Validate outbound transports do not downgrade security."""

    def test_rejects_plaintext_smtp_auth_before_connecting(self, monkeypatch):
        smtp_called = False

        def fake_smtp(*args, **kwargs):
            nonlocal smtp_called
            smtp_called = True
            raise AssertionError("SMTP should not be opened for plaintext auth")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fake_smtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "secret",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        assert smtp_called is False

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        class FakeSMTP:
            starttls_context = None

            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context):
                FakeSMTP.starttls_context = context

            def login(self, username, password):
                pass

            def send_message(self, message):
                pass

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
                "username": "user",
                "password": "secret",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(FakeSMTP.starttls_context, ssl.SSLContext)
        assert FakeSMTP.starttls_context.check_hostname is True
        assert FakeSMTP.starttls_context.verify_mode == ssl.CERT_REQUIRED

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        captured_kwargs = {}

        class FakeResponse:
            status = 200

            async def text(self):
                return ""

        class FakePostContext:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured_kwargs.update(kwargs)
                return FakePostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/services/test"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False
