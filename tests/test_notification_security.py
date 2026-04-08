"""Security tests for notification webhook URL and transport validation."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="must not include user credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_fragment_in_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="must not include URL fragments"):
            svc._validate_webhook_url("https://example.com/webhook#frag")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationTransportHardening:
    """Validate transport-level security hardening for notifications."""

    @pytest.mark.parametrize(
        "channel_key,message_method,channel",
        [
            ("slack", "_send_slack", NotificationChannel.SLACK),
            ("discord", "_send_discord", NotificationChannel.DISCORD),
            ("webhook", "_send_webhook", NotificationChannel.WEBHOOK),
        ],
    )
    def test_channel_requests_disable_redirect_following(
        self, monkeypatch, channel_key, message_method, channel
    ):
        captured: dict[str, object] = {}

        class _DummyResponse:
            status = 200

            async def text(self):
                return "ok"

        class _PostContext:
            async def __aenter__(self):
                return _DummyResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _PostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _DummySession)
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )

        svc = EnhancedNotificationService()
        if channel_key == "webhook":
            svc.config["webhook"]["url"] = "https://example.com/hook"
        else:
            svc.config[channel_key]["webhook_url"] = "https://example.com/hook"

        message = NotificationMessage(
            title="Security test",
            content="redirect behavior",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

        send_fn = getattr(svc, message_method)
        result = asyncio.run(send_fn(message))
        assert result.get("success") is True
        assert captured.get("allow_redirects") is False

    def test_email_uses_verified_tls_context(self, monkeypatch):
        captured: dict[str, object] = {"tls_context": None}

        class _DummySMTP:
            def __init__(self, host, port):
                self.host = host
                self.port = port

            def starttls(self, context=None):
                captured["tls_context"] = context

            def login(self, _user, _password):
                return None

            def send_message(self, _msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["a@example.com"],
                "use_tls": True,
                "username": "user",
                "password": "pass",
            }
        )

        message = NotificationMessage(
            title="TLS test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result.get("success") is True
        assert captured["tls_context"] is not None

    def test_email_rejects_auth_without_tls(self, monkeypatch):
        class _DummySMTP:
            def __init__(self, host, port):
                self.host = host
                self.port = port

            def starttls(self, context=None):
                return None

            def login(self, _user, _password):
                raise AssertionError("login should not be called without TLS")

            def send_message(self, _msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["a@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "pass",
            }
        )

        message = NotificationMessage(
            title="TLS disabled test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result.get("success") is False
        assert "without TLS" in str(result.get("error"))
