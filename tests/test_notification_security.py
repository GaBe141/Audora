"""Security tests for notification webhook URL validation."""

import asyncio
from pathlib import Path

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

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_webhook_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_attachment_paths_must_stay_within_project_root(self, tmp_path):
        svc = EnhancedNotificationService()
        project_root = tmp_path / "project"
        project_root.mkdir()
        allowed = project_root / "safe.txt"
        allowed.write_text("safe", encoding="utf-8")

        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")

        svc.project_root = project_root
        resolved = svc._resolve_attachment_path("safe.txt")
        assert resolved == allowed.resolve()

        with pytest.raises(ValueError, match="project directory"):
            svc._resolve_attachment_path(str(outside))

    def test_webhook_post_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        captured: dict[str, object] = {}

        class DummyResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return DummyResponse()

        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, allow_private=False: url
        )
        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", lambda: DummySession())

        message = NotificationMessage(
            title="Test",
            content="Test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert captured.get("allow_redirects") is False
