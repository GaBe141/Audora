"""Security tests for notification webhook URL validation."""

from unittest.mock import patch

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
        with (
            patch.object(svc, "_resolve_webhook_hostname", return_value={"10.0.0.1"}),
            pytest.raises(ValueError, match="private or restricted"),
        ):
            svc._validate_webhook_url("https://example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://example.com/webhook"
        with patch.object(svc, "_resolve_webhook_hostname", return_value={"10.0.0.1"}):
            validated_url, hostname, resolved_ips = svc._validate_webhook_destination(
                url, allow_private=True
            )
        assert validated_url == url
        assert hostname == "example.com"
        assert resolved_ips == {"10.0.0.1"}

    def test_builds_connector_with_validated_resolver(self):
        svc = EnhancedNotificationService()
        with patch.object(svc, "_resolve_webhook_hostname", return_value={"93.184.216.34"}):
            url, connector = svc._build_webhook_connector("https://example.com/webhook")

        assert url == "https://example.com/webhook"
        assert connector._resolver.resolved_ips == {"93.184.216.34"}
        connector.close()
