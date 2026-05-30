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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeClientSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return _FakeResponse(self.status)


def _test_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="Test notification",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class TestWebhookTransportSecurity:
    """Validate transport hardening for outbound webhook sends."""

    def test_slack_send_disables_redirects(self, monkeypatch):
        fake_session = _FakeClientSession()
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_slack(_test_message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert fake_session.post_calls[0][1]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self, monkeypatch):
        fake_session = _FakeClientSession(status=204)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_discord(_test_message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert fake_session.post_calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        fake_session = _FakeClientSession()
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: fake_session)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        result = asyncio.run(svc._send_webhook(_test_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert fake_session.post_calls[0][1]["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP TLS handling before credentials are sent."""

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        contexts = []

        class FakeSmtp:
            def __init__(self, *_args, **_kwargs):
                self.logged_in = False

            def starttls(self, *, context):
                contexts.append(context)

            def login(self, _username, _password):
                self.logged_in = True

            def send_message(self, _message):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSmtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_test_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED

    def test_refuses_plaintext_smtp_auth(self, monkeypatch):
        class FakeSmtp:
            def __init__(self, *_args, **_kwargs):
                pass

            def login(self, _username, _password):
                raise AssertionError("login should not be called without TLS")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSmtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(_test_message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "without TLS" in result["error"]
