"""Security tests for notification URL validation and outbound request hardening."""

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


class _MockResponse:
    def __init__(self, status: int = 200, text_value: str = "ok"):
        self.status = status
        self._text_value = text_value

    async def text(self) -> str:
        return self._text_value


class _MockPostContext:
    def __init__(self, response: _MockResponse):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _MockSession:
    def __init__(self, calls: list[dict]):
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self._calls.append({"url": url, "kwargs": kwargs})
        return _MockPostContext(_MockResponse())


class TestOutboundWebhookSecurity:
    """Ensure outbound webhook requests keep redirect protections enabled."""

    def test_send_webhook_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert calls, "Expected outbound webhook request"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_send_slack_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        result = asyncio.run(svc._send_slack(msg))

        assert result["success"] is True
        assert calls, "Expected outbound Slack request"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_send_discord_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        result = asyncio.run(svc._send_discord(msg))

        assert result["success"] is True
        assert calls, "Expected outbound Discord request"
        assert calls[0]["kwargs"]["allow_redirects"] is False


class _MockSMTP:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.starttls_called = False
        self.starttls_context = None
        self.login_called = False
        self.sent_message = False
        self.quit_called = False

    def starttls(self, context=None):
        self.starttls_called = True
        self.starttls_context = context

    def login(self, username: str, password: str):
        self.login_called = True

    def send_message(self, _msg):
        self.sent_message = True

    def quit(self):
        self.quit_called = True


class TestEmailTransportSecurity:
    """Ensure SMTP notifications use verified TLS context."""

    def test_send_email_uses_verified_tls_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }

        created_contexts: list[object] = []
        mock_context = object()

        def fake_create_default_context():
            created_contexts.append(mock_context)
            return mock_context

        smtp_instances: list[_MockSMTP] = []

        def fake_smtp(host: str, port: int):
            smtp = _MockSMTP(host, port)
            smtp_instances.append(smtp)
            return smtp

        monkeypatch.setattr("core.notification_service.ssl.create_default_context", fake_create_default_context)
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fake_smtp)

        msg = NotificationMessage(
            title="Email test",
            content="Secure email body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert len(created_contexts) == 1
        assert smtp_instances, "Expected SMTP client to be created"
        smtp = smtp_instances[0]
        assert smtp.starttls_called is True
        assert smtp.starttls_context is mock_context
        assert smtp.login_called is True
        assert smtp.sent_message is True
        assert smtp.quit_called is True
