"""Security tests for notification webhook URL validation."""

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

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_generate_message_key_uses_stable_sha256(self):
        svc = EnhancedNotificationService()
        msg = NotificationMessage(
            title="Security Event",
            content="Potentially sensitive notification content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        key1 = svc._generate_message_key(msg)
        key2 = svc._generate_message_key(msg)

        digest, suffix = key1.split(":")
        assert key1 == key2
        assert len(digest) == 64
        assert suffix == NotificationPriority.HIGH.value

    def test_attachment_path_must_stay_within_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        svc = EnhancedNotificationService()

        safe = tmp_path / "report.txt"
        safe.write_text("ok", encoding="utf-8")
        assert svc._is_safe_attachment_path(str(safe)) is True
        assert svc._is_safe_attachment_path("../outside.txt") is False

    def test_send_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        msg = NotificationMessage(
            title="Security Event",
            content="Body",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.WEBHOOK],
        )

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda u, allow_private=False: u)
        captured: dict[str, bool] = {}

        class _FakeResponse:
            status = 200

            async def text(self):
                return "ok"

        class _PostContext:
            def __init__(self, kwargs):
                self.kwargs = kwargs

            async def __aenter__(self):
                captured["allow_redirects"] = self.kwargs.get("allow_redirects")
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                return _PostContext(kwargs)

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        result = asyncio.run(svc._send_webhook(msg))
        assert result["success"] is True
        assert captured.get("allow_redirects") is False
