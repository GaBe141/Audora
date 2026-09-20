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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:token@example.com/webhook")


class TestEmailAndConfigHardening:
    """Header injection, attachment confinement, and config path checks."""

    def test_strips_crlf_from_header_values(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header_value("Hello\r\nBcc: attacker@example.com") == (
            "HelloBcc: attacker@example.com"
        )

    def test_rejects_attachment_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        assert svc._safe_attachment_path(str(outside)) is None

    def test_save_config_rejects_path_escape(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config").mkdir()
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config"):
            svc.save_config(str(tmp_path / "stolen.json"))
