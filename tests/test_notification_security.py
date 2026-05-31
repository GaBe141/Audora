"""Security tests for notification webhook URL validation."""

import asyncio
import json
import socket

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


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

    def test_prepare_webhook_request_pins_validated_dns_results(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("8.8.8.8", port),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        url, connector = svc._prepare_webhook_request("https://example.com/webhook")
        try:
            records = asyncio.run(connector._resolver.resolve("example.com", 443))
        finally:
            asyncio.run(connector.close())

        assert url == "https://example.com/webhook"
        assert records[0]["host"] == "8.8.8.8"

    def test_custom_webhook_rejects_private_targets_even_with_legacy_env_flag(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://10.0.0.1/webhook"
        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is False
        assert "private or restricted" in result["error"]

    def test_save_config_does_not_persist_smtp_password(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        data = json.loads(config_path.read_text())
        assert "password" not in data["email"]
