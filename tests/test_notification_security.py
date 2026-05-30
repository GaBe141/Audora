"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import EnhancedNotificationService, StaticWebhookResolver
from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority


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

    def test_rejects_urls_with_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_urls_with_fragments(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="fragments"):
            svc._validate_webhook_url("https://example.com/webhook#token")

    def test_static_resolver_only_returns_validated_host(self):
        resolver = StaticWebhookResolver("example.com", 443, {"93.184.216.34"})

        async def resolve_validated_host():
            return await resolver.resolve("example.com", 443)

        results = asyncio.run(resolve_validated_host())
        assert results[0]["host"] == "93.184.216.34"

        async def resolve_unexpected_host():
            return await resolver.resolve("internal.example", 443)

        with pytest.raises(OSError, match="Unexpected"):
            asyncio.run(resolve_unexpected_host())


class TestEmailSecurity:
    """Validate SMTP credential handling."""

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="Message",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result == {"success": False, "error": "SMTP authentication requires TLS"}
