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
    """Async context manager that mimics an aiohttp response."""

    status = 302

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "redirect"


class _FakeSession:
    """Async context manager that captures post kwargs."""

    def __init__(self, captured_kwargs):
        self.captured_kwargs = captured_kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, _url, **kwargs):
        self.captured_kwargs.append(kwargs)
        return _FakeResponse()


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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    @pytest.mark.parametrize(
        ("channel", "config_key", "url_key", "sender_name"),
        [
            (NotificationChannel.SLACK, "slack", "webhook_url", "_send_slack"),
            (NotificationChannel.DISCORD, "discord", "webhook_url", "_send_discord"),
            (NotificationChannel.WEBHOOK, "webhook", "url", "_send_webhook"),
        ],
    )
    def test_webhook_senders_do_not_follow_redirects(
        self, monkeypatch, channel, config_key, url_key, sender_name
    ):
        captured_kwargs = []

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(captured_kwargs),
        )

        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_kwargs: url)
        svc.config[config_key][url_key] = "https://example.com/webhook"

        message = NotificationMessage(
            title="redirect test",
            content="redirect test",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

        result = asyncio.run(getattr(svc, sender_name)(message))

        assert result["success"] is False
        assert captured_kwargs
        assert captured_kwargs[0]["allow_redirects"] is False


class _FakeSMTP:
    """Small SMTP fake that records TLS and auth usage."""

    instances = []

    def __init__(self, _server, _port):
        self.starttls_context = None
        self.login_called = False
        self.send_called = False
        self.quit_called = False
        self.__class__.instances.append(self)

    def starttls(self, context=None):
        self.starttls_context = context

    def login(self, _username, _password):
        self.login_called = True

    def send_message(self, _message):
        self.send_called = True

    def quit(self):
        self.quit_called = True


class TestEmailTransportSecurity:
    """Validate SMTP credentials are protected in transit."""

    def test_refuses_smtp_auth_without_tls(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        _FakeSMTP.instances = []

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert _FakeSMTP.instances == []

    def test_smtp_starttls_uses_validating_ssl_context(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        _FakeSMTP.instances = []

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        smtp = _FakeSMTP.instances[0]
        assert result["success"] is True
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.login_called is True
        assert smtp.send_called is True
        assert smtp.quit_called is True

    def _message(self):
        return NotificationMessage(
            title="SMTP security test",
            content="SMTP security test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
