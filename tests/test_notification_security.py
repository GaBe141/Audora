"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

import pytest

from core import notification_service
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

    def test_rejects_unapproved_channel_hosts_before_dns_lookup(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="not allowed"):
            svc._validate_webhook_url(
                "https://evil.example/webhook",
                allowed_hosts={"hooks.slack.com"},
            )


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeClientSession:
    instances = []

    def __init__(self):
        self.post_kwargs = None
        self.__class__.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, _url, **kwargs):
        self.post_kwargs = kwargs
        return _FakeResponse()


class TestNotificationTransportHardening:
    """Validate outbound notification transports are hardened."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        _FakeClientSession.instances = []
        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", _FakeClientSession)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, **_kwargs: url,
        )

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeClientSession.instances[0].post_kwargs["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        _FakeClientSession.instances = []
        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", _FakeClientSession)

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/B/C"
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, **_kwargs: url,
        )

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakeClientSession.instances[0].post_kwargs["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        contexts = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context):
                contexts.append(context)

            def login(self, *_args):
                pass

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        monkeypatch.setattr(notification_service.smtplib, "SMTP", FakeSMTP)
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
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED

    def test_smtp_rejects_plaintext_credentials(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def login(self, *_args):
                raise AssertionError("login should not be called without TLS")

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        monkeypatch.setattr(notification_service.smtplib, "SMTP", FakeSMTP)
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
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]
