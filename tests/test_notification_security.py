"""Security tests for notification outbound safety controls."""

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

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        captured: dict[str, object] = {}

        class MockResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class MockSession:
            def post(self, url, **kwargs):
                captured["url"] = url
                captured.update(kwargs)
                return MockResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", MockSession)

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="Security check",
                    content="redirect should not be followed",
                    priority=NotificationPriority.HIGH,
                    channels=[NotificationChannel.WEBHOOK],
                )
            )
        )

        assert result["success"] is False
        assert captured["allow_redirects"] is False


class TestEmailAttachmentValidation:
    """Validate email attachment file access restrictions."""

    def test_resolves_attachment_inside_allowed_directory(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        attachment = allowed_dir / "summary.txt"
        attachment.write_text("ok", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["allowed_attachment_dirs"] = [str(allowed_dir)]

        assert svc._resolve_attachment_path(str(attachment)) == attachment.resolve()

    def test_rejects_attachment_outside_allowed_directory(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        secret = tmp_path / ".env"
        secret.write_text("SECRET=do-not-read", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["allowed_attachment_dirs"] = [str(allowed_dir)]

        with pytest.raises(ValueError, match="outside allowed"):
            svc._resolve_attachment_path(str(secret))

    def test_rejects_attachment_symlink_escape(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        secret = tmp_path / ".env"
        secret.write_text("SECRET=do-not-read", encoding="utf-8")
        link = allowed_dir / "summary.txt"
        link.symlink_to(secret)

        svc = EnhancedNotificationService()
        svc.config["allowed_attachment_dirs"] = [str(allowed_dir)]

        with pytest.raises(ValueError, match="outside allowed"):
            svc._resolve_attachment_path(str(link))

    def test_rejects_oversized_attachment(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        attachment = allowed_dir / "large.txt"
        attachment.write_text("too large", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["allowed_attachment_dirs"] = [str(allowed_dir)]
        svc.config["max_attachment_bytes"] = 1

        with pytest.raises(ValueError, match="size limit"):
            svc._resolve_attachment_path(str(attachment))
