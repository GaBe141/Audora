"""Security tests for notification webhook URL validation."""

import pytest

from core.notification_service import EnhancedNotificationService


class TestWebhookUrlValidation:
    """Validate SSRF protections for outbound webhooks."""

    def test_rejects_non_https_urls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="HTTPS"):
            svc._validate_webhook_url("http://example.com/webhook")

    def test_rejects_control_characters(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="invalid characters"):
            svc._validate_webhook_url("https://example.com/hook\r\nX-Injected: yes")

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

    def test_blocks_cgnat_and_metadata_even_when_private_is_allowed(self):
        svc = EnhancedNotificationService()
        blocked = [
            "https://100.100.100.200/hook",
            "https://192.88.99.1/hook",
            "https://[fec0::1]/hook",
            "https://[fd00:ec2::254]/hook",
            "https://[2001::1]/hook",
            "https://[64:ff9b::8.8.8.8]/hook",
        ]
        for url in blocked:
            with pytest.raises(ValueError, match="private or restricted"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_allows_mapped_rfc1918_only_with_private_opt_in(self):
        svc = EnhancedNotificationService()
        url = "https://[::ffff:10.0.0.1]/webhook"
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=False)
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_smtp_blocks_private_and_metadata_with_smtp_wording(self, monkeypatch):
        monkeypatch.delenv("AUDORA_ALLOW_PRIVATE_SMTP", raising=False)
        svc = EnhancedNotificationService()
        for host in ("10.0.0.1", "2001::1", "100.100.100.200"):
            with pytest.raises(ValueError, match="SMTP server") as caught:
                svc._validate_smtp_host(host)
            assert "Webhook URL" not in str(caught.value)
