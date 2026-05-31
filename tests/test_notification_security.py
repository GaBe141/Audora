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
    """Validate secure outbound transport options."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    def test_smtp_starttls_uses_default_ssl_context(self, monkeypatch):
        contexts = []
        sentinel_context = object()

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context):
                contexts.append(context)

            def login(self, *_args, **_kwargs):
                pass

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: sentinel_context,
        )

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "password",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert contexts == [sentinel_context]

    def test_smtp_refuses_plaintext_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "password",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_webhook_posts_disable_redirects(self, monkeypatch):
        calls = []

        class FakeResponse:
            status = 302

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def text(self):
                return "redirect"

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            def post(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["webhook"] = {
            "url": "https://example.com/webhook",
            "headers": {"Content-Type": "application/json"},
            "timeout": 30,
        }

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is False
        assert "redirects" in result["error"]
        assert calls[0][1]["allow_redirects"] is False
