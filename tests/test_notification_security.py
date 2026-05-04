"""Security tests for notification webhook URL validation."""

import socket
from unittest.mock import Mock

import aiohttp
import pytest

from core.notification_service import EnhancedNotificationService, StaticWebhookResolver


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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_prepare_destination_pins_validated_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *args, **kwargs: [
                (None, None, None, None, ("93.184.216.34", 443)),
            ],
        )

        destination = svc._prepare_webhook_destination("https://example.com/webhook")

        assert destination.hostname == "example.com"
        assert destination.port == 443
        assert destination.resolved_ips == ("93.184.216.34",)

    @pytest.mark.asyncio
    async def test_static_resolver_only_returns_prevalidated_addresses(self):
        resolver = StaticWebhookResolver({"example.com": ("93.184.216.34",)})

        result = await resolver.resolve("example.com", 443)

        assert result == [
            {
                "hostname": "example.com",
                "host": "93.184.216.34",
                "port": 443,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

        with pytest.raises(OSError, match="pre-validated"):
            await resolver.resolve("metadata.google.internal", 443)

    @pytest.mark.asyncio
    async def test_webhook_posts_disable_redirects_and_use_pinned_resolver(self, monkeypatch):
        svc = EnhancedNotificationService()
        destination = svc._prepare_webhook_destination("https://10.0.0.1/webhook", allow_private=True)
        post = Mock()

        class Response:
            status = 302

            async def text(self):
                return "redirect blocked"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

        class Session:
            def __init__(self, *, connector, timeout):
                self.connector = connector
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, *args, **kwargs):
                post(*args, **kwargs)
                return Response()

        captured = {}

        def fake_session(*, connector, timeout):
            captured["connector"] = connector
            captured["timeout"] = timeout
            return Session(connector=connector, timeout=timeout)

        monkeypatch.setattr(aiohttp, "ClientSession", fake_session)

        status, response_text = await svc._post_json_to_webhook(
            destination,
            {"ok": True},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )

        assert status == 302
        assert response_text == "redirect blocked"
        _, kwargs = post.call_args
        assert kwargs["allow_redirects"] is False
        assert captured["connector"]._resolver.destinations == {"10.0.0.1": ("10.0.0.1",)}
