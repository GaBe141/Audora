"""Security tests for notification webhook URL validation."""

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


class _FakeResponse:
    status = 200

    async def text(self):
        return ""


class _FakePostContext:
    def __init__(self, calls, url, kwargs):
        self.calls = calls
        self.url = url
        self.kwargs = kwargs

    async def __aenter__(self):
        self.calls.append((self.url, self.kwargs))
        return _FakeResponse()

    async def __aexit__(self, *_args):
        return False


class _FakeClientSession:
    calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def post(self, url, **kwargs):
        return _FakePostContext(self.calls, url, kwargs)


class TestWebhookTransportHardening:
    """Validate outbound webhook transport protections."""

    def setup_method(self):
        _FakeClientSession.calls = []

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, **_kwargs: url
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/example"

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakeClientSession.calls[0][1]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, **_kwargs: url
        svc.config["discord"]["webhook_url"] = "https://discord.test/webhook"

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert _FakeClientSession.calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, **_kwargs: url
        svc.config["webhook"]["url"] = "https://webhook.test/audora"

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeClientSession.calls[0][1]["allow_redirects"] is False


class TestEmailTransportHardening:
    """Validate SMTP transport security choices."""

    def test_smtp_starttls_uses_default_ssl_context(self, monkeypatch):
        contexts = []

        class FakeSMTP:
            def __init__(self, *_args):
                pass

            def starttls(self, context=None):
                contexts.append(context)

            def send_message(self, _msg):
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
                "username": "",
                "password": "",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True

    def test_smtp_auth_without_tls_is_rejected(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, *_args):
                pass

            def login(self, *_args):
                raise AssertionError("login should not be called without TLS")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "password",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]
