"""Security tests for notification transport hardening."""

import asyncio
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "redirect"


class _FakeClientSession:
    post_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append({"args": args, "kwargs": kwargs})
        return _FakeResponse(302)


class TestWebhookTransportSecurity:
    """Validate outbound webhook sends do not follow redirects."""

    @pytest.fixture(autouse=True)
    def clear_calls(self):
        _FakeClientSession.post_calls.clear()

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Security alert",
            content="Test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

    def test_slack_disables_redirects(self, monkeypatch, message):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", _FakeClientSession
        )
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, *, allow_private=False: url
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is False
        assert _FakeClientSession.post_calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch, message):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", _FakeClientSession
        )
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, *, allow_private=False: url
        )

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is False
        assert _FakeClientSession.post_calls[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch, message):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", _FakeClientSession
        )
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, *, allow_private=False: url
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is False
        assert _FakeClientSession.post_calls[0]["kwargs"]["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP credentials are sent only over verified TLS."""

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security alert",
            content="Test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = svc._send_email(message)

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        class FakeSmtp:
            starttls_context = None

            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context):
                FakeSmtp.starttls_context = context

            def login(self, username, password):
                pass

            def send_message(self, msg):
                pass

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSmtp)
        message = NotificationMessage(
            title="Security alert",
            content="Test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = svc._send_email(message)

        assert result["success"] is True
        assert FakeSmtp.starttls_context is not None
        assert FakeSmtp.starttls_context.check_hostname is True
        assert FakeSmtp.starttls_context.verify_mode.name == "CERT_REQUIRED"
