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

    def test_rejects_loopback_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/webhook", allow_private=True)

    def test_rejects_link_local_metadata_address(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_rejects_decimal_loopback_literal(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://2130706433/webhook", allow_private=True)

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/webhook", allow_private=True)

    def test_rejects_localhost_suffix(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://evil.localhost/webhook")

    def test_rejects_metadata_hostname(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Metadata"):
            svc._validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_rejects_credentials_in_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@10.0.0.1/webhook", allow_private=True)

    def test_rejects_ambiguous_ip_literal(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="ambiguous"):
            svc._validate_webhook_url("https://0177.0.0.1/webhook")

    def test_config_path_cannot_escape_config_directory(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config("/tmp/notification_config.json")
