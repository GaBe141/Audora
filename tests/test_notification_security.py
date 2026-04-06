"""Security tests for notification transport and webhook validation."""

import asyncio
from typing import Any

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class _FakeResponseContext:
    """Async context manager returning a fake HTTP response."""

    def __init__(self, status: int = 200, text: str = "ok") -> None:
        self.status = status
        self._text = text

    async def __aenter__(self) -> "_FakeResponseContext":
        return self

    async def __aexit__(self, _exc_type, _exc, _tb) -> bool:
        return False

    async def text(self) -> str:
        return self._text


class _RecordingClientSession:
    """Fake aiohttp session that records POST kwargs."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.last_post_kwargs: dict[str, Any] | None = None
        self.last_post_url: str | None = None

    async def __aenter__(self) -> "_RecordingClientSession":
        return self

    async def __aexit__(self, _exc_type, _exc, _tb) -> bool:
        return False

    def post(self, url: str, **kwargs: Any) -> _FakeResponseContext:
        self.last_post_url = url
        self.last_post_kwargs = kwargs
        return _FakeResponseContext(status=self.status)


class _RecordingSMTP:
    """Fake SMTP client that records TLS context usage."""

    instances: list["_RecordingSMTP"] = []

    def __init__(self, _host: str, _port: int) -> None:
        self.starttls_context = None
        self.logged_in = False
        self.sent = False
        _RecordingSMTP.instances.append(self)

    def starttls(self, context=None) -> None:
        self.starttls_context = context

    def login(self, _username: str, _password: str) -> None:
        self.logged_in = True

    def send_message(self, _msg) -> None:
        self.sent = True

    def quit(self) -> None:
        return None


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Security Test",
        content="payload",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.WEBHOOK],
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


class TestNotificationTransportSecurity:
    """Validate transport-level security controls."""

    def test_omits_empty_webhook_authorization_header(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()
        headers = svc.config["webhook"]["headers"]
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_webhook_post_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        fake_session = _RecordingClientSession(status=200)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert fake_session.last_post_kwargs is not None
        assert fake_session.last_post_kwargs.get("allow_redirects") is False

    def test_slack_post_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        fake_session = _RecordingClientSession(status=200)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        result = asyncio.run(svc._send_slack(_message()))
        assert result["success"] is True
        assert fake_session.last_post_kwargs is not None
        assert fake_session.last_post_kwargs.get("allow_redirects") is False

    def test_discord_post_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        fake_session = _RecordingClientSession(status=204)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        result = asyncio.run(svc._send_discord(_message()))
        assert result["success"] is True
        assert fake_session.last_post_kwargs is not None
        assert fake_session.last_post_kwargs.get("allow_redirects") is False

    def test_email_starttls_uses_default_ssl_context(self, monkeypatch):
        _RecordingSMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _RecordingSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        assert _RecordingSMTP.instances
        smtp_client = _RecordingSMTP.instances[0]
        assert smtp_client.starttls_context is not None
