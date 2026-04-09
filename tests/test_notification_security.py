"""Security tests for notification webhook URL validation."""

from pathlib import Path

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


class TestNotificationAttachmentValidation:
    """Validate email attachment path safety checks."""

    def test_rejects_attachment_outside_allowed_directory(self, tmp_path):
        svc = EnhancedNotificationService()

        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="outside allowed directories"):
            svc._resolve_attachment_path(str(outside_file))

    def test_allows_attachment_inside_allowed_directory(self):
        svc = EnhancedNotificationService()

        allowed_root = Path.cwd() / "data"
        allowed_root.mkdir(parents=True, exist_ok=True)
        allowed_file = allowed_root / "ok.txt"
        allowed_file.write_text("ok", encoding="utf-8")

        validated = svc._resolve_attachment_path(str(allowed_file))
        assert validated == Path(allowed_file).resolve()
