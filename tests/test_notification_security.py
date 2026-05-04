"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import EnhancedNotificationService, PublicOnlyResolver


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

    def test_public_only_resolver_rejects_private_dns_answers(self):
        resolver = PublicOnlyResolver()
        private_addr = (10, 1, 2, 3)
        socket_result = [
            (
                private_addr[0],
                private_addr[1],
                private_addr[2],
                "",
                (private_addr[3], 443),
            )
        ]

        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=socket_result),
            pytest.raises(ValueError, match="private or restricted"),
        ):
            asyncio.run(resolver.resolve("example.com", 443))

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/audora"
        message = MagicMock()
        message.title = "Title"
        message.content = "Content"
        message.priority.value = "low"
        message.data = {}
        message.template_vars = None

        response = MagicMock()
        response.status = 200

        async def response_text():
            return ""

        response.text = response_text
        post_context = MagicMock()
        post_context.__aenter__.return_value = response
        post_context.__aexit__.return_value = None

        session = MagicMock()
        session.post.return_value = post_context
        session_context = MagicMock()
        session_context.__aenter__.return_value = session
        session_context.__aexit__.return_value = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch.object(svc, "_public_only_connector", return_value=MagicMock()),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_context),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False
