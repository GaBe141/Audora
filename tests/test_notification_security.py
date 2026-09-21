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

    def test_rejects_credential_urls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")

    def test_rejects_decimal_loopback_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Numeric"):
            svc._validate_webhook_url("https://2130706433/hook")

    def test_rejects_non_canonical_ipv4(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="non-canonical"):
            svc._validate_webhook_url("https://127.0.0.01/hook")

    def test_rejects_ipv4_mapped_private_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.1.1.1]/hook")

    def test_rejects_config_path_outside_config_dir(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secrets.json"
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(outside))

    def test_rejects_attachment_outside_data_dir(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        with pytest.raises(ValueError, match="data directory"):
            svc._resolve_attachment_path(str(outside))
