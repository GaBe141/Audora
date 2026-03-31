"""Security tests for notification transport protections."""

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


class _FakeSMTP:
    """Small SMTP test double to verify TLS and login behavior."""

    instances: list["_FakeSMTP"] = []

    def __init__(self, _host, _port):
        self.__class__.instances.append(self)
        self.ehlo_calls = 0
        self.starttls_context = None
        self.login_called = False
        self.quit_called = False
        self.send_message_called = False

    def ehlo(self):
        self.ehlo_calls += 1

    def starttls(self, context=None):
        self.starttls_context = context

    def login(self, _username, _password):
        self.login_called = True

    def send_message(self, _msg):
        self.send_message_called = True

    def quit(self):
        self.quit_called = True


class _FakeResponseCtx:
    def __init__(self, status=200, body="ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        return False

    async def text(self):
        return self._body


class _FakeSession:
    """aiohttp ClientSession test double to capture post kwargs."""

    def __init__(self, calls: list[dict], status=200):
        self.calls = calls
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return _FakeResponseCtx(status=self.status)


class TestNotificationTransportSecurity:
    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["user@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        _FakeSMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        tls_context = object()
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: tls_context,
        )

        msg = NotificationMessage(
            title="transport test",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        smtp = _FakeSMTP.instances[-1]
        assert smtp.starttls_context is tls_context
        assert smtp.ehlo_calls >= 2

    def test_refuses_smtp_auth_when_tls_disabled(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 25,
                "recipients": ["user@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "secret",
            }
        )
        _FakeSMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        msg = NotificationMessage(
            title="transport test",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp = _FakeSMTP.instances[-1]
        assert smtp.login_called is False
        assert smtp.quit_called is True

    def test_webhook_posts_disable_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        calls: list[dict] = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(calls, status=200),
        )

        msg = NotificationMessage(
            title="webhook test",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert calls, "expected a webhook POST call"
        assert calls[0]["kwargs"]["allow_redirects"] is False
