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
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self):
        self.post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, _url, **kwargs):
        self.post_kwargs = kwargs
        return _FakeResponse()


class TestNotificationTransportSecurity:
    """Validate outbound transports do not weaken TLS or follow redirects."""

    def test_slack_webhook_redirects_are_disabled(self, monkeypatch):
        import core.notification_service as notification_service

        fake_session = _FakeSession()
        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", lambda: fake_session)

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T000/B000/XXX"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert fake_session.post_kwargs["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        fake_smtp = _FakeSMTP()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *_args: fake_smtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(fake_smtp.tls_context, ssl.SSLContext)
        assert fake_smtp.tls_context.check_hostname is True
        assert fake_smtp.tls_context.verify_mode == ssl.CERT_REQUIRED

    def test_smtp_auth_without_tls_is_rejected(self, monkeypatch):
        fake_smtp = _FakeSMTP()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *_args: fake_smtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "secret",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert fake_smtp.logged_in is False


class _FakeSMTP:
    def __init__(self):
        self.tls_context = None
        self.logged_in = False

    def starttls(self, *, context=None):
        self.tls_context = context

    def login(self, *_args):
        self.logged_in = True

    def send_message(self, _message):
        return None

    def quit(self):
        return None
