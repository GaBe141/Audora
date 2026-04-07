"""Security tests for notification webhook URL validation."""

import socket
from urllib.parse import urlparse

import pytest

from core.notification_service import EnhancedNotificationService, _PinnedResolver


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

    def test_rejects_embedded_url_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookDeliveryHardening:
    """Validate runtime webhook delivery hardening."""

    @pytest.mark.asyncio
    async def test_send_webhook_rejects_http_redirect(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        class DummyResponse:
            def __init__(self, status: int, text: str):
                self.status = status
                self._text = text

            async def text(self):
                return self._text

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                assert kwargs["allow_redirects"] is False
                return DummyResponse(302, "redirect blocked")

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)
        monkeypatch.setattr(
            svc,
            "_create_pinned_connector",
            lambda url, allow_private: (url, object()),
        )

        from core.notification_service import NotificationMessage, NotificationPriority

        result = await svc._send_webhook(
            NotificationMessage(
                title="Test",
                content="Security test",
                priority=NotificationPriority.LOW,
                channels=[],
            )
        )
        assert result["success"] is False
        assert "HTTP 302" in result["error"]

    def test_create_pinned_connector_uses_validated_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()
        test_url = "https://example.com/notify"
        parsed = urlparse(test_url)
        test_port = parsed.port or 443

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: test_url,
        )

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda host, port, proto=0: [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
            ],
        )

        validated_url, connector = svc._create_pinned_connector(test_url, allow_private=False)
        assert validated_url == test_url
        resolver = connector._resolver
        assert isinstance(resolver, _PinnedResolver)
        assert resolver._hostname == parsed.hostname
        assert resolver._port == test_port
        assert resolver._addresses == ("93.184.216.34",)
