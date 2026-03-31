"""Security tests for notification webhook URL validation."""

from unittest.mock import patch

import pytest

from core.notification_service import EnhancedNotificationService


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

    @pytest.mark.asyncio
    async def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        captured: dict[str, object] = {}

        class _Response:
            status = 200

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _Response()

        msg = type("Msg", (), {})()
        msg.title = "Test"
        msg.content = "Body"
        msg.priority = type("Priority", (), {"value": "low"})()
        msg.data = {}
        msg.template_vars = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/webhook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()),
        ):
            result = await svc._send_webhook(msg)  # type: ignore[arg-type]

        assert result["success"] is True
        assert captured.get("allow_redirects") is False
