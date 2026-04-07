"""Security tests for notification webhook URL validation and attachment safety."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_fragment(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="URL fragment"):
            svc._validate_webhook_url("https://example.com/webhook#frag")


class TestAttachmentPathValidation:
    """Validate attachment path constraints."""

    def test_rejects_attachment_outside_allowed_root(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_root = tmp_path / "exports"
        allowed_root.mkdir(parents=True, exist_ok=True)
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="outside allowed directory"):
            svc._resolve_attachment_path(str(outside_file), allowed_root.resolve())

    def test_allows_attachment_within_allowed_root(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_root = tmp_path / "exports"
        allowed_root.mkdir(parents=True, exist_ok=True)
        safe_file = allowed_root / "report.csv"
        safe_file.write_text("a,b\n1,2\n", encoding="utf-8")

        resolved = svc._resolve_attachment_path(str(safe_file), allowed_root.resolve())
        assert resolved == safe_file.resolve()
