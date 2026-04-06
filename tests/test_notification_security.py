"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
from unittest.mock import Mock

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


class _MockAioHttpResponse:
    def __init__(self, status=200, text_body="ok"):
        self.status = status
        self._text_body = text_body

    async def text(self):
        return self._text_body


class _MockAioHttpRequestContext:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _MockAioHttpSession:
    def __init__(self, recorder, response):
        self._recorder = recorder
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self._recorder.append({"args": args, "kwargs": kwargs})
        return _MockAioHttpRequestContext(self._response)


@pytest.mark.asyncio
async def test_slack_post_disables_redirects(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["slack"]["webhook_url"] = "https://example.com/slack"
    recorder = []
    response = _MockAioHttpResponse(status=200)

    monkeypatch.setattr(
        "core.notification_service.aiohttp.ClientSession",
        lambda *args, **kwargs: _MockAioHttpSession(recorder, response),
    )
    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,
    )

    message = NotificationMessage(
        title="Test",
        content="Test content",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.SLACK],
    )
    result = await svc._send_slack(message)

    assert result["success"] is True
    assert recorder, "Expected Slack request to be made"
    assert recorder[0]["kwargs"].get("allow_redirects") is False


@pytest.mark.asyncio
async def test_discord_post_disables_redirects(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["discord"]["webhook_url"] = "https://example.com/discord"
    recorder = []
    response = _MockAioHttpResponse(status=204)

    monkeypatch.setattr(
        "core.notification_service.aiohttp.ClientSession",
        lambda *args, **kwargs: _MockAioHttpSession(recorder, response),
    )
    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,
    )

    message = NotificationMessage(
        title="Test",
        content="Test content",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.DISCORD],
    )
    result = await svc._send_discord(message)

    assert result["success"] is True
    assert recorder, "Expected Discord request to be made"
    assert recorder[0]["kwargs"].get("allow_redirects") is False


@pytest.mark.asyncio
async def test_webhook_post_disables_redirects(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    recorder = []
    response = _MockAioHttpResponse(status=200)

    monkeypatch.setattr(
        "core.notification_service.aiohttp.ClientSession",
        lambda *args, **kwargs: _MockAioHttpSession(recorder, response),
    )
    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,
    )

    message = NotificationMessage(
        title="Test",
        content="Test content",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )
    result = await svc._send_webhook(message)

    assert result["success"] is True
    assert recorder, "Expected webhook request to be made"
    assert recorder[0]["kwargs"].get("allow_redirects") is False


def test_email_starttls_uses_secure_ssl_context(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"].update(
        {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "noreply@example.com",
            "recipients": ["recipient@example.com"],
            "use_tls": True,
        }
    )

    server = Mock()
    monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *args, **kwargs: server)

    message = NotificationMessage(
        title="Email test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )
    result = asyncio.run(svc._send_email(message))

    assert result["success"] is True
    assert server.starttls.called
    kwargs = server.starttls.call_args.kwargs
    assert "context" in kwargs
    context = kwargs["context"]
    assert context.verify_mode is not None
    assert context.check_hostname is True


def test_email_rejects_smtp_auth_without_tls():
    svc = EnhancedNotificationService()
    svc.config["email"].update(
        {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "noreply@example.com",
            "recipients": ["recipient@example.com"],
            "use_tls": False,
        }
    )

    message = NotificationMessage(
        title="Email test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )

    result = asyncio.run(svc._send_email(message))
    assert result["success"] is False
    assert "requires TLS" in result["error"]
