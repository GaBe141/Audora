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
    def __init__(self, status: int):
        self.status = status

    async def text(self):
        return ""


class _FakePostContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeClientSession:
    def __init__(self, status: int):
        self.response = _FakeResponse(status)
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.posts.append((args, kwargs))
        return _FakePostContext(self.response)


class _FakeSMTP:
    def __init__(self):
        self.starttls_context = None
        self.logged_in = False
        self.sent = False
        self.quit_called = False

    def starttls(self, *, context):
        self.starttls_context = context

    def login(self, username, password):
        self.logged_in = True

    def send_message(self, message):
        self.sent = True

    def quit(self):
        self.quit_called = True


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


class TestWebhookTransportHardening:
    """Validate webhook transports cannot follow redirect-chain SSRF hops."""

    @pytest.mark.parametrize(
        ("method_name", "config_key", "url_key", "channel", "status"),
        [
            ("_send_slack", "slack", "webhook_url", NotificationChannel.SLACK, 200),
            ("_send_discord", "discord", "webhook_url", NotificationChannel.DISCORD, 204),
            ("_send_webhook", "webhook", "url", NotificationChannel.WEBHOOK, 204),
        ],
    )
    def test_webhook_sends_disable_redirects(
        self, monkeypatch, method_name, config_key, url_key, channel, status
    ):
        svc = EnhancedNotificationService()
        svc.config[config_key][url_key] = "https://example.com/webhook"
        fake_session = _FakeClientSession(status)

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: fake_session,
        )

        message = NotificationMessage(
            title="Test",
            content="Webhook hardening test",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

        result = asyncio.run(getattr(svc, method_name)(message))

        assert result["success"] is True
        assert fake_session.posts[0][1]["allow_redirects"] is False


class TestEmailTransportHardening:
    """Validate SMTP authentication only happens over verified TLS."""

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        smtp = _FakeSMTP()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *args: smtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Email hardening test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.logged_in is True
        assert smtp.sent is True
        assert smtp.quit_called is True

    def test_smtp_auth_requires_tls(self, monkeypatch):
        smtp = _FakeSMTP()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *args: smtp)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Email hardening test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        assert smtp.logged_in is False
        assert smtp.sent is False
        assert smtp.quit_called is True
