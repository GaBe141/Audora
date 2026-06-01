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

    def test_save_config_rejects_invalid_webhook_url(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://localhost/webhook"

        with pytest.raises(ValueError, match="Localhost"):
            svc.save_config(str(tmp_path / "notification_config.json"))


class TestEmailAttachmentValidation:
    """Validate attachment path boundaries for email notifications."""

    def test_allows_existing_files_under_export_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        export_dir = tmp_path / "data" / "exports"
        export_dir.mkdir(parents=True)
        report_path = export_dir / "report.csv"
        report_path.write_text("track,score\nSong,99\n", encoding="utf-8")

        svc = EnhancedNotificationService()

        assert svc._resolve_attachment_path(str(report_path)) == report_path.resolve()

    def test_rejects_existing_files_outside_export_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data" / "exports").mkdir(parents=True)
        secret_path = tmp_path / "secret.txt"
        secret_path.write_text("do not attach\n", encoding="utf-8")

        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="export directory"):
            svc._resolve_attachment_path(str(secret_path))
