"""Security tests for notification webhook URL validation."""

import socket

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

    @staticmethod
    def _public_dns_result():
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]

    def test_accepts_valid_slack_webhook_url(self, monkeypatch):
        svc = EnhancedNotificationService()
        url = "https://hooks.slack.com/services/T000/B000/abc123"
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: self._public_dns_result())
        assert svc._validate_slack_webhook_url(url) == url

    def test_rejects_invalid_slack_webhook_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Slack webhook URL must use one of"):
            svc._validate_slack_webhook_url("https://evil.example.com/services/T000/B000/abc123")

    def test_rejects_invalid_slack_webhook_path(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Slack webhook URL path is invalid"):
            svc._validate_slack_webhook_url("https://hooks.slack.com/api/webhooks/not-a-slack-path")

    def test_accepts_valid_discord_webhook_url(self, monkeypatch):
        svc = EnhancedNotificationService()
        url = "https://discord.com/api/webhooks/123456/token-abc"
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: self._public_dns_result())
        assert svc._validate_discord_webhook_url(url) == url

    def test_rejects_invalid_discord_webhook_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Discord webhook URL must use one of"):
            svc._validate_discord_webhook_url("https://example.com/api/webhooks/123456/token-abc")

    def test_rejects_invalid_discord_webhook_path(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Discord webhook URL path is invalid"):
            svc._validate_discord_webhook_url("https://discord.com/webhooks/123456/token-abc")
