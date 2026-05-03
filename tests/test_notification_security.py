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

    def test_prepared_webhook_uses_pinned_validated_dns_answers(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, type=0, proto=0):
            assert host == "example.com"
            assert port == 443
            assert type == socket.SOCK_STREAM
            assert proto == socket.IPPROTO_TCP
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        target = svc._prepare_webhook_target("https://example.com/webhook")
        assert target.url == "https://example.com/webhook"
        assert target.connector._resolver.resolved_hosts[0]["host"] == "93.184.216.34"


class TestNotificationConfigPersistence:
    """Validate that saved notification config excludes secrets by default."""

    def test_does_not_persist_long_lived_secrets_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDORA_PERSIST_NOTIFICATION_SECRETS", raising=False)
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/E/S"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/token"
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = config_path.read_text(encoding="utf-8")
        assert "smtp-secret" not in saved
        assert "hooks.slack.com" not in saved
        assert "discord.com/api/webhooks" not in saved
        assert "https://example.com/webhook" not in saved
        assert "Bearer token" not in saved
        assert "sms-key" not in saved
        assert "sms-secret" not in saved
