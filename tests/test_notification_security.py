"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import MagicMock, patch

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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeClientSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, *args, **kwargs):
        _FakeClientSession.last_post_kwargs = kwargs
        return _FakeResponse()


class TestWebhookTransportSecurity:
    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/E/S"
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/2"
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert _FakeClientSession.last_post_kwargs["allow_redirects"] is False


class TestEmailTransportSecurity:
    def _message(self, content: str = "content") -> NotificationMessage:
        return NotificationMessage(
            title="Email test",
            content=content,
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

    def test_smtp_starttls_uses_verified_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )
        server = MagicMock()
        context = object()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch("core.notification_service.ssl.create_default_context", return_value=context),
        ):
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        server.starttls.assert_called_once_with(context=context)

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        server = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        server.login.assert_not_called()

    def test_html_email_body_escapes_message_content(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "",
                "password": "",
                "use_tls": True,
            }
        )
        server = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch("core.notification_service.ssl.create_default_context", return_value=object()),
        ):
            result = asyncio.run(svc._send_email(self._message("<script>alert(1)</script>")))

        assert result["success"] is True
        sent_message = server.send_message.call_args.args[0]
        html_body = sent_message.get_payload()[1].get_payload()
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body
        assert "<script>alert(1)</script>" not in html_body
