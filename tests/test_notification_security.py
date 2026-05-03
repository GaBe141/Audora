"""Security tests for notification webhook URL validation."""

import json
import socket
from pathlib import Path

import pytest

from core.notification_service import EnhancedNotificationService, _PinnedWebhookResolver
from integrations.api_config import APIConfig, SocialAPIManager


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

    def test_validated_target_retains_approved_dns_answers(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ],
        )

        target = svc._validate_webhook_target("https://example.com/webhook")

        assert target.hostname == "example.com"
        assert target.resolved_hosts[0]["host"] == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_pinned_resolver_rejects_unvalidated_hosts(self):
        resolver = _PinnedWebhookResolver(
            "example.com",
            443,
            (
                {
                    "hostname": "example.com",
                    "host": "93.184.216.34",
                    "port": 443,
                    "family": socket.AF_INET,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                },
            ),
        )

        with pytest.raises(OSError, match="refused"):
            await resolver.resolve("metadata.google.internal", 443)

    def test_save_config_does_not_persist_secrets(self, tmp_path: Path):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/secret"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/secret"
        svc.config["webhook"]["url"] = "https://example.com/secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["username"] = "admin"
        svc.config["email"]["password"] = "secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved_text = config_path.read_text(encoding="utf-8")
        saved = json.loads(saved_text)
        assert "secret" not in saved_text
        assert "webhook_url" not in saved["slack"]
        assert "smtp_server" not in saved["email"]
        assert "headers" not in saved["webhook"]

    def test_social_api_config_does_not_persist_credentials(self, tmp_path: Path):
        config_path = tmp_path / "social_apis.json"
        manager = SocialAPIManager(config_file=str(config_path))
        manager.configs["youtube"] = APIConfig(
            platform="youtube",
            api_key="youtube-secret",
            access_token="token-secret",
            enabled=True,
        )

        manager.save_configs()

        saved_text = config_path.read_text(encoding="utf-8")
        saved = json.loads(saved_text)
        assert "secret" not in saved_text
        assert "api_key" not in saved["youtube"]
        assert "access_token" not in saved["youtube"]
