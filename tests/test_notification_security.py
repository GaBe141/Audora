"""Security tests for notification webhook URL validation."""

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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestAttachmentPathValidation:
    """Validate path traversal protections for notification attachments."""

    def test_allows_attachment_within_project_root(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path

        attachment = tmp_path / "reports" / "summary.txt"
        attachment.parent.mkdir(parents=True, exist_ok=True)
        attachment.write_text("ok", encoding="utf-8")

        resolved = svc._resolve_attachment_path("reports/summary.txt")
        assert resolved == attachment.resolve()

    def test_rejects_attachment_outside_project_root(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path

        outside_file = tmp_path.parent / "outside-secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="within project root"):
            svc._resolve_attachment_path(str(outside_file))

    def test_rejects_oversized_attachments(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        svc.max_attachment_bytes = 5

        attachment = tmp_path / "reports" / "big.txt"
        attachment.parent.mkdir(parents=True, exist_ok=True)
        attachment.write_text("this is larger than five bytes", encoding="utf-8")

        with pytest.raises(ValueError, match="maximum allowed size"):
            svc._resolve_attachment_path("reports/big.txt")
