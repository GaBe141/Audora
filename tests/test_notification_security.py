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

    def test_builds_connector_with_static_validated_resolver(self, monkeypatch):
        svc = EnhancedNotificationService()
        records = [
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ]
        monkeypatch.setattr("socket.getaddrinfo", lambda *_, **__: records)

        connector = svc._build_webhook_connector("https://example.com/webhook")

        assert connector._use_dns_cache is False
        assert connector._resolver._records[("example.com", 443)][0]["host"] == "93.184.216.34"
        awaitable = connector.close()
        if awaitable:
            awaitable.close()

    def test_default_webhook_headers_omit_blank_authorization(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()

        assert svc.config["webhook"]["headers"] == {"Content-Type": "application/json"}
