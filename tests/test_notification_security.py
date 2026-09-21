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

    def test_rejects_localhost_with_trailing_dot(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://localhost./webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_ipv4_mapped_private_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.0.0.1]/webhook")

    def test_rejects_decimal_loopback_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://2130706433/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationConfigAndEmailSafety:
    """Validate config path confinement and header sanitization."""

    def test_save_config_rejects_paths_outside_config_dir(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(tmp_path / "evil.json"))

    def test_sanitize_header_strips_crlf(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header_value("Subject\r\nBcc: attacker@example.com") == (
            "SubjectBcc: attacker@example.com"
        )

    def test_rejects_attachment_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        assert svc._is_safe_attachment_path(str(outside)) is False

    def test_allows_attachment_inside_project(self):
        svc = EnhancedNotificationService()
        inside = Path(__file__).resolve().parent.parent / "README.md"
        assert svc._is_safe_attachment_path(str(inside)) is True
