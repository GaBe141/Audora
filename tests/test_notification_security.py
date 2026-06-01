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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:password@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_env_flag_does_not_allow_private_webhooks(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "1")
        svc = EnhancedNotificationService()

        assert svc._allow_private_webhooks() is False


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    captured_posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.captured_posts.append({"url": url, "kwargs": kwargs})
        return _FakeResponse()


class TestWebhookTransport:
    """Validate outbound webhook transports cannot follow redirect chains."""

    def setup_method(self):
        _FakeSession.captured_posts = []

    def _message(self, channel):
        return NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    def _allow_example_dns(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )

    def test_slack_send_disables_redirects(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert _FakeSession.captured_posts[0]["kwargs"]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert _FakeSession.captured_posts[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert _FakeSession.captured_posts[0]["kwargs"]["allow_redirects"] is False


class TestEmailSecurity:
    """Validate SMTP credential and header safety."""

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["recipient@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_starttls_uses_validating_ssl_context(self, monkeypatch):
        contexts = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, context):
                contexts.append(context)

            def login(self, *_args):
                pass

            def send_message(self, *_args):
                pass

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["recipient@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        monkeypatch.setattr(svc, "_validate_smtp_host", lambda host: host)
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED

    def test_email_subject_strips_newlines(self):
        svc = EnhancedNotificationService()

        assert svc._sanitize_email_header("Hello\r\nBcc: attacker@example.com") == (
            "Hello  Bcc: attacker@example.com"
        )

    def _message(self):
        return NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
