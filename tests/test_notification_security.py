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

    def test_rejects_credentials_in_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_decimal_and_padded_ip_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="non-canonical"):
            svc._validate_webhook_url("https://2130706433/webhook")
        with pytest.raises(ValueError, match="non-canonical"):
            svc._validate_webhook_url("https://127.0.0.01/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted|non-canonical|Localhost"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/webhook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:7f00:1]/webhook")

    def test_rejects_attachment_outside_data_dir(self):
        svc = EnhancedNotificationService()
        assert svc._confine_attachment("/etc/passwd") is None

    def test_rejects_config_path_escape(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="escapes allowed directory"):
            svc._confine_config_path(str(tmp_path / "notification_config.json"))
