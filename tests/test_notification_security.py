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

    def test_rejects_embedded_credentials(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def text(self):
        return ""


class _FakeClientSession:
    def __init__(self, captured_posts):
        self._captured_posts = captured_posts

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def post(self, url, **kwargs):
        self._captured_posts.append({"url": url, **kwargs})
        return _FakeResponse()


def _message(channel):
    return NotificationMessage(
        title="Security test",
        content="payload",
        priority=NotificationPriority.HIGH,
        channels=[channel],
    )


class TestWebhookTransportSecurity:
    """Validate outbound webhook transport settings that prevent SSRF bypasses."""

    @pytest.fixture(autouse=True)
    def public_dns(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        captured_posts = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(captured_posts),
        )
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert captured_posts[0]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        captured_posts = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(captured_posts),
        )
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert captured_posts[0]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        captured_posts = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(captured_posts),
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom"

        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert captured_posts[0]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, server, port):
                captured["server"] = server
                captured["port"] = port

            def starttls(self, *, context):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, message):
                captured["subject"] = message["Subject"]

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "secret",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert captured["login"] == ("user", "secret")

    def test_plaintext_smtp_auth_is_rejected_before_connecting(self, monkeypatch):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("SMTP should not be opened when credentials lack TLS")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fail_if_called)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
