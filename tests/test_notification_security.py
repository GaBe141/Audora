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


class _FakeResponseContext:
    status = 302

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def text(self):
        return "redirect"


class _FakeSession:
    def __init__(self, captured_posts):
        self._captured_posts = captured_posts

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def post(self, url, **kwargs):
        self._captured_posts.append((url, kwargs))
        return _FakeResponseContext()


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


class TestNotificationTransportHardening:
    """Validate outbound transport hardening for notification channels."""

    @pytest.mark.parametrize(
        ("channel_key", "url_key", "method_name", "channel"),
        [
            ("slack", "webhook_url", "_send_slack", NotificationChannel.SLACK),
            ("discord", "webhook_url", "_send_discord", NotificationChannel.DISCORD),
            ("webhook", "url", "_send_webhook", NotificationChannel.WEBHOOK),
        ],
    )
    def test_webhook_channels_do_not_follow_redirects(
        self, monkeypatch, channel_key, url_key, method_name, channel
    ):
        captured_posts = []
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(captured_posts),
        )

        svc = EnhancedNotificationService()
        svc.config[channel_key][url_key] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        message = NotificationMessage(
            title="Test",
            content="Test notification",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

        result = asyncio.run(getattr(svc, method_name)(message))

        assert result["success"] is False
        assert captured_posts
        assert captured_posts[0][1]["allow_redirects"] is False

    def test_smtp_starttls_uses_validating_ssl_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, message):
                captured["message"] = message

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Test notification",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert captured["context"].check_hostname is True

    def test_refuses_smtp_auth_without_tls(self, monkeypatch):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("SMTP should not be opened when credentials require TLS")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fail_if_called)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "pass",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Test notification",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "TLS" in result["error"]
