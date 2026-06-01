"""Security tests for notification webhook URL validation."""

import asyncio

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
    """Validate hardened outbound notification transports."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, *, allow_private=False: url,
        )

        captured_kwargs = {}

        class MockResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class MockSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return MockResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", MockSession)

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)

        captured_kwargs = {}

        class MockResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class MockSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return MockResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", MockSession)

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)

        captured_kwargs = {}

        class MockResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class MockSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return MockResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", MockSession)

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        captured_context = None

        class MockSMTP:
            def __init__(self, _host, _port):
                pass

            def starttls(self, *, context):
                nonlocal captured_context
                captured_context = context

            def login(self, _username, _password):
                pass

            def send_message(self, _message):
                pass

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", MockSMTP)

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert captured_context is not None
        assert captured_context.check_hostname is True
        assert captured_context.verify_mode.name == "CERT_REQUIRED"

    def test_smtp_auth_without_tls_is_rejected(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]
