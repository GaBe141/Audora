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

    def test_custom_webhook_auth_header_requires_allowed_host(self):
        svc = EnhancedNotificationService()
        headers = svc._headers_for_webhook(
            "https://attacker.example/webhook",
            {
                "headers": {"Content-Type": "application/json"},
                "auth_token": "secret-token",
                "auth_allowed_hosts": ["trusted.example"],
            },
        )

        assert "Authorization" not in headers

    def test_custom_webhook_auth_header_sent_to_allowed_host(self):
        svc = EnhancedNotificationService()
        headers = svc._headers_for_webhook(
            "https://trusted.example/webhook",
            {
                "headers": {"Content-Type": "application/json"},
                "auth_token": "secret-token",
                "auth_allowed_hosts": ["trusted.example"],
            },
        )

        assert headers["Authorization"] == "Bearer secret-token"

    def test_custom_webhook_configured_authorization_header_is_replaced(self):
        svc = EnhancedNotificationService()
        headers = svc._headers_for_webhook(
            "https://trusted.example/webhook",
            {
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer attacker-controlled",
                },
                "auth_token": "trusted-token",
                "auth_allowed_hosts": ["trusted.example"],
            },
        )

        assert headers["Authorization"] == "Bearer trusted-token"

    def test_custom_webhook_legacy_authorization_header_is_stripped_even_for_allowed_host(self):
        svc = EnhancedNotificationService()
        headers = svc._headers_for_webhook(
            "https://trusted.example/webhook",
            {
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer legacy-secret",
                },
                "auth_allowed_hosts": ["trusted.example"],
            },
        )

        assert "Authorization" not in headers
