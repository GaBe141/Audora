"""Security tests for notification delivery hardening."""

import asyncio
import socket

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    StaticWebhookResolver,
    WebhookTarget,
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

    def test_returns_pinned_public_addresses(self, monkeypatch):
        def fake_getaddrinfo(host, port, proto):
            assert host == "example.com"
            assert port == 443
            assert proto == socket.IPPROTO_TCP
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        svc = EnhancedNotificationService()

        target = svc._validate_webhook_target(" https://example.com/webhook ")

        assert target == WebhookTarget(
            url="https://example.com/webhook",
            hostname="example.com",
            resolved_ips=("93.184.216.34",),
        )


class TestWebhookResolver:
    """Validate that webhook sessions only resolve prevalidated addresses."""

    def test_rejects_unexpected_hostname(self):
        resolver = StaticWebhookResolver("example.com", ("93.184.216.34",))

        with pytest.raises(OSError, match="unexpected hostname"):
            asyncio.run(resolver.resolve("attacker.example", 443))


class TestWebhookDelivery:
    """Validate outbound webhook requests do not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured_kwargs = {}

        class FakeResponse:
            status = 302

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return "redirect"

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            svc,
            "_validate_webhook_target",
            lambda url, allow_private=False: WebhookTarget(
                url=url, hostname="example.com", resolved_ips=("93.184.216.34",)
            ),
        )
        monkeypatch.setattr(svc, "_create_webhook_session", lambda _target: FakeSession())
        message = NotificationMessage(
            title="Test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is False
        assert captured_kwargs["allow_redirects"] is False


class TestEmailSecurity:
    """Validate SMTP credentials are only sent over TLS."""

    def test_refuses_credentials_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "use_tls": False,
                "username": "user",
                "password": "secret",
                "recipients": ["ops@example.com"],
            }
        )
        message = NotificationMessage(
            title="Test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result == {
            "success": False,
            "error": "Refusing to send SMTP credentials without TLS",
        }
