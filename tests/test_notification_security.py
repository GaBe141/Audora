"""Security tests for notification webhook URL validation and transport hardening."""

import ssl
from types import SimpleNamespace
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


@pytest.mark.asyncio
async def test_webhook_post_disables_redirects(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/hook"

    monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

    captured: dict[str, object] = {}

    class _FakeResponse:
        status = 200

        async def text(self):
            return ""

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def post(self, url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return _FakeResponse()

    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _FakeSession())

    message = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )
    result = await svc._send_webhook(message)
    assert result["success"] is True
    assert captured["allow_redirects"] is False


def test_email_starttls_uses_verified_context(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"]["smtp_server"] = "smtp.example.com"
    svc.config["email"]["recipients"] = ["user@example.com"]
    svc.config["email"]["username"] = "user"
    svc.config["email"]["password"] = "secret"
    svc.config["email"]["use_tls"] = True

    captured: dict[str, object] = {}

    class _FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def starttls(self, context=None):
            captured["tls_context"] = context

        def login(self, username, password):
            captured["login"] = (username, password)

        def send_message(self, msg):
            captured["sent"] = True

        def quit(self):
            captured["quit"] = True

    monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *args, **kwargs: _FakeSMTP())
    message = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )
    import asyncio

    result = asyncio.run(svc._send_email(message))

    assert result["success"] is True
    tls_context = captured.get("tls_context")
    assert isinstance(tls_context, ssl.SSLContext)
    assert tls_context.verify_mode == ssl.CERT_REQUIRED
    assert tls_context.check_hostname is True


def test_email_rejects_plaintext_auth_without_tls():
    svc = EnhancedNotificationService()
    svc.config["email"]["smtp_server"] = "smtp.example.com"
    svc.config["email"]["recipients"] = ["user@example.com"]
    svc.config["email"]["username"] = "user"
    svc.config["email"]["password"] = "secret"
    svc.config["email"]["use_tls"] = False

    import asyncio

    message = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )
    result = asyncio.run(svc._send_email(message))
    assert result["success"] is False
    assert "requires TLS" in result["error"]
