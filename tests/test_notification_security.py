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


class _FakeResponse:
    def __init__(self, status: int = 200, text: str = ""):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return self._text


class _FakeSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.posts: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, url: str, **kwargs):
        self.posts.append((url, kwargs))
        return _FakeResponse(self.status)


def _message(channels: list[NotificationChannel] | None = None) -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="payload",
        priority=NotificationPriority.HIGH,
        channels=channels or [NotificationChannel.WEBHOOK],
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransport:
    """Validate outbound webhook transport options."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        fake_session = _FakeSession()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/webhook"
        svc._create_webhook_session = lambda url, allow_private=False: (url, fake_session)

        result = asyncio.run(svc._send_slack(_message([NotificationChannel.SLACK])))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        fake_session = _FakeSession(status=204)
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        svc._create_webhook_session = lambda url, allow_private=False: (url, fake_session)

        result = asyncio.run(svc._send_discord(_message([NotificationChannel.DISCORD])))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        fake_session = _FakeSession()
        svc.config["webhook"]["url"] = "https://hooks.example/webhook"
        svc._create_webhook_session = lambda url, allow_private=False: (url, fake_session)

        result = asyncio.run(svc._send_webhook(_message([NotificationChannel.WEBHOOK])))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False


class TestEmailTransport:
    """Validate SMTP transport security."""

    def test_email_uses_verified_starttls_context(self, monkeypatch):
        starttls_contexts = []

        class FakeSMTP:
            def __init__(self, host, port):
                self.host = host
                self.port = port

            def starttls(self, *, context):
                starttls_contexts.append(context)

            def send_message(self, msg):
                return None

            def quit(self):
                return None

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

        result = asyncio.run(svc._send_email(_message([NotificationChannel.EMAIL])))

        assert result["success"] is True
        assert isinstance(starttls_contexts[0], ssl.SSLContext)
        assert starttls_contexts[0].check_hostname is True
        assert starttls_contexts[0].verify_mode == ssl.CERT_REQUIRED

    def test_email_refuses_plaintext_smtp_auth(self, monkeypatch):
        class FailIfCalledSMTP:
            def __init__(self, host, port):
                raise AssertionError("SMTP should not be opened for plaintext auth")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FailIfCalledSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "secret",
            }
        )

        result = asyncio.run(svc._send_email(_message([NotificationChannel.EMAIL])))

        assert result["success"] is False
        assert "TLS" in result["error"]
