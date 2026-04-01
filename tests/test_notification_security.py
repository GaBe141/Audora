"""Security tests for notification webhook URL validation."""

import asyncio
from email.mime.multipart import MIMEMultipart

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
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return "ok"


class _FakeSession:
    def __init__(self, calls: list[dict]):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse(status=200)


class TestWebhookRedirectProtection:
    """Ensure outbound webhook requests cannot follow redirects."""

    def test_slack_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        message = NotificationMessage(
            title="test",
            content="redirect test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert calls and calls[0]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        message = NotificationMessage(
            title="test",
            content="redirect test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert calls and calls[0]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        calls: list[dict] = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls),
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        message = NotificationMessage(
            title="test",
            content="redirect test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert calls and calls[0]["allow_redirects"] is False


class _FakeSMTP:
    instances: list["_FakeSMTP"] = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.starttls_called = False
        self.starttls_context = None
        self.login_called = False
        self.quit_called = False
        self.ehlo_calls = 0
        self.sent_messages = []
        _FakeSMTP.instances.append(self)

    def ehlo(self):
        self.ehlo_calls += 1

    def starttls(self, context=None):
        self.starttls_called = True
        self.starttls_context = context

    def login(self, username, password):
        self.login_called = True

    def send_message(self, message):
        assert isinstance(message, MIMEMultipart)
        self.sent_messages.append(message)

    def quit(self):
        self.quit_called = True


class TestSmtpTransportSecurity:
    """Ensure SMTP notifications enforce secure transport."""

    def test_email_auth_requires_tls(self, monkeypatch):
        _FakeSMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "bot@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        msg = NotificationMessage(
            title="test",
            content="secure transport check",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert _FakeSMTP.instances
        smtp_instance = _FakeSMTP.instances[0]
        assert smtp_instance.starttls_called is False
        assert smtp_instance.login_called is False

    def test_email_starttls_uses_default_ssl_context(self, monkeypatch):
        _FakeSMTP.instances.clear()
        captured_contexts = []

        def _fake_default_context():
            marker = object()
            captured_contexts.append(marker)
            return marker

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context", _fake_default_context
        )
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "bot@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        msg = NotificationMessage(
            title="test",
            content="tls context check",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is True
        assert _FakeSMTP.instances
        smtp_instance = _FakeSMTP.instances[0]
        assert smtp_instance.starttls_called is True
        assert smtp_instance.starttls_context is captured_contexts[0]
        assert smtp_instance.ehlo_calls == 2
        assert smtp_instance.login_called is True
