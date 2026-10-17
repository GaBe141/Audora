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

    def test_rejects_cgnat_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.100.100.200/hook", allow_private=True)

    def test_rejects_decimal_and_obfuscated_loopback_hosts(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://2130706433/hook",
            "https://127.1/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
        ):
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_rejects_userinfo_and_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)

    def test_allows_mapped_private_address_when_opted_in(self):
        svc = EnhancedNotificationService()
        url = "https://[::ffff:10.0.0.1]/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_metadata_ranges_explicitly(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://192.88.99.1/hook",
            "https://[fec0::1]/hook",
            "https://[fd00:ec2::254]/hook",
            "https://[64:ff9b::1]/hook",
            "https://[2002::1]/hook",
        ):
            with pytest.raises(ValueError, match="private or restricted"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_save_config_rejects_absolute_path(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="relative"):
            svc.save_config(str(tmp_path / "notification_config.json"))
