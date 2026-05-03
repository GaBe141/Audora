"""Security tests for notification delivery safeguards."""

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


class TestEmailAttachmentValidation:
    """Validate that email attachments cannot exfiltrate arbitrary local files."""

    def test_allows_generated_data_attachments(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        attachment = tmp_path / "data" / "reports" / "summary.json"
        attachment.parent.mkdir(parents=True)
        attachment.write_text("{}", encoding="utf-8")

        assert svc._safe_attachment_path("data/reports/summary.json") == attachment.resolve()

    def test_rejects_paths_outside_generated_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        secret_file = tmp_path / ".env"
        secret_file.write_text("TOKEN=secret", encoding="utf-8")

        assert svc._safe_attachment_path(".env") is None

    def test_rejects_path_traversal_outside_generated_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        outside_file = tmp_path.parent / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        assert svc._safe_attachment_path("../secret.txt") is None
