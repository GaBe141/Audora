"""Security tests for notification transport and webhook validation."""

import asyncio

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _MockResponse:
    def __init__(self, status: int, text: str = ""):
        self.status = status
        self._text = text

    async def text(self) -> str:
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _MockSession:
    def __init__(self, response: _MockResponse):
        self._response = response
        self.last_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, _url, **kwargs):
        self.last_kwargs = kwargs
        return self._response


def test_webhook_post_disables_redirect_following(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/hook"
    svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
    svc.config["webhook"]["timeout"] = 5

    monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

    mock_session = _MockSession(_MockResponse(200))
    monkeypatch.setattr(aiohttp, "ClientSession", lambda: mock_session)

    msg = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )
    result = asyncio.run(svc._send_webhook(msg))
    assert result["success"] is True
    assert mock_session.last_kwargs is not None
    assert mock_session.last_kwargs.get("allow_redirects") is False


def test_email_rejects_plaintext_auth_without_tls():
    svc = EnhancedNotificationService()
    svc.config["email"].update(
        {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
    )
    msg = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )
    result = asyncio.run(svc._send_email(msg))
    assert result["success"] is False
    assert "without TLS" in result["error"]


def test_email_starttls_uses_ssl_context(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"].update(
        {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
    )

    captured: dict[str, object] = {}

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def starttls(self, context=None):
            captured["context"] = context

        def login(self, *_args, **_kwargs):
            return None

        def send_message(self, *_args, **_kwargs):
            return None

        def quit(self):
            return None

    monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
    msg = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )

    result = asyncio.run(svc._send_email(msg))
    assert result["success"] is True
    assert captured.get("context") is not None


def test_slack_redirects_are_rejected(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["slack"]["webhook_url"] = "https://example.com/slack"
    monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

    mock_session = _MockSession(_MockResponse(302, "moved"))
    monkeypatch.setattr(aiohttp, "ClientSession", lambda: mock_session)

    msg = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.SLACK],
    )
    result = asyncio.run(svc._send_slack(msg))
    assert result["success"] is False
    assert "redirect rejected" in result["error"].lower()
    assert mock_session.last_kwargs is not None
    assert mock_session.last_kwargs.get("allow_redirects") is False


def test_discord_redirects_are_rejected(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["discord"]["webhook_url"] = "https://example.com/discord"
    monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

    mock_session = _MockSession(_MockResponse(302, "moved"))
    monkeypatch.setattr(aiohttp, "ClientSession", lambda: mock_session)

    msg = NotificationMessage(
        title="t",
        content="c",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.DISCORD],
    )
    result = asyncio.run(svc._send_discord(msg))
    assert result["success"] is False
    assert "redirect rejected" in result["error"].lower()
    assert mock_session.last_kwargs is not None
    assert mock_session.last_kwargs.get("allow_redirects") is False
