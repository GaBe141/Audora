"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio

import pytest

import core.notification_service as notification_service
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationTransportHardening:
    """Validate outbound transports do not weaken URL validation."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="Payload",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

    def _public_dns(self, monkeypatch):
        monkeypatch.setattr(
            notification_service.socket,
            "getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )

    def _capture_client_session(self, monkeypatch):
        post_kwargs = []

        class FakeResponse:
            status = 200

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                post_kwargs.append(kwargs)
                return FakeResponse()

        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", FakeSession)
        return post_kwargs

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        self._public_dns(monkeypatch)
        post_kwargs = self._capture_client_session(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example/slack"

        result = asyncio.run(svc._send_slack(self._message()))

        assert result["success"] is True
        assert post_kwargs[0]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        self._public_dns(monkeypatch)
        post_kwargs = self._capture_client_session(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example/discord"

        result = asyncio.run(svc._send_discord(self._message()))

        assert result["success"] is True
        assert post_kwargs[0]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        self._public_dns(monkeypatch)
        post_kwargs = self._capture_client_session(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example/custom"

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert post_kwargs[0]["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        contexts = []
        sent_messages = []
        expected_context = object()

        class FakeSMTP:
            def __init__(self, server, port):
                self.server = server
                self.port = port

            def starttls(self, context=None):
                contexts.append(context)

            def login(self, username, password):
                pass

            def send_message(self, message):
                sent_messages.append(message)

            def quit(self):
                pass

        monkeypatch.setattr(notification_service.ssl, "create_default_context", lambda: expected_context)
        monkeypatch.setattr(notification_service.smtplib, "SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        assert contexts == [expected_context]
        assert sent_messages

    def test_smtp_refuses_credentials_without_tls(self, monkeypatch):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("SMTP connection should not be opened")

        monkeypatch.setattr(notification_service.smtplib, "SMTP", fail_if_called)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
