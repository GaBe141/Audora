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

    def test_blocks_cgnat_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.100.100.200/hook", allow_private=True)

    def test_blocks_ipv4_mapped_loopback_and_metadata(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://[::ffff:127.0.0.1]/hook",
            "https://[::ffff:169.254.169.254]/hook",
            "https://[::1]/hook",
        ):
            with pytest.raises(ValueError, match="private or restricted|Localhost"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_blocks_nat64_and_6to4_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://[64:ff9b::808:808]/hook",
            "https://[64:ff9b:1::1]/hook",
            "https://[2002:7f00:1::]/hook",
            "https://[fec0::1]/hook",
            "https://192.88.99.1/hook",
        ):
            with pytest.raises(ValueError, match="private or restricted"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_rejects_userinfo_numeric_and_obfuscated_hosts(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        for url in (
            "https://2130706433/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
            "https://127.1/hook",
        ):
            with pytest.raises(ValueError, match="Numeric|private or restricted|Localhost"):
                svc._validate_webhook_url(url)

    def test_smtp_rejects_metadata_and_nonstandard_ports(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="465 or 587"):
            svc._validate_smtp_target("smtp.example.com", 25)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_target("169.254.169.254", 587)
