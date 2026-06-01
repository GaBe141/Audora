"""Security tests for notification webhook URL validation and secret handling."""

import asyncio
import json

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    RestrictedWebhookResolver,
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

    def test_custom_webhook_rejects_private_ip_even_with_legacy_env_bypass(self, monkeypatch):
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


class TestNotificationSecretPersistence:
    """Ensure file-backed notification config never persists bearer secrets."""

    def test_save_config_strips_secret_values(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/TOKEN"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/TOKEN"
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        svc.config["webhook"]["headers"]["authorization"] = "Bearer lower"
        svc.config["webhook"]["headers"]["Proxy-Authorization"] = "Bearer proxy"
        svc.config["webhook"]["headers"]["X-API-Key"] = "api-key-secret"
        svc.config["webhook"]["headers"]["Content-Type"] = "application/json"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "webhook_url" not in saved["slack"]
        assert "webhook_url" not in saved["discord"]
        assert "url" not in saved["webhook"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "authorization" not in saved["webhook"]["headers"]
        assert "Proxy-Authorization" not in saved["webhook"]["headers"]
        assert "X-API-Key" not in saved["webhook"]["headers"]
        assert saved["webhook"]["headers"] == {"Content-Type": "application/json"}
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]

    def test_load_config_ignores_secret_values_from_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SMTP_PASSWORD", "env-smtp-secret")
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/ENV")
        monkeypatch.setenv("WEBHOOK_TOKEN", "env-webhook-token")
        config_path = tmp_path / "notification_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "email": {
                        "smtp_server": "smtp.example.com",
                        "password": "file-smtp-secret",
                    },
                    "slack": {
                        "webhook_url": "https://hooks.slack.com/services/FILE",
                    },
                    "webhook": {
                        "headers": {
                            "authorization": "Bearer lower-file",
                            "Proxy-Authorization": "Bearer proxy-file",
                            "X-API-Key": "file-api-key",
                            "Content-Type": "application/json",
                        },
                    },
                }
            )
        )

        svc = EnhancedNotificationService(config_file=str(config_path))

        assert svc.config["email"]["smtp_server"] == "smtp.example.com"
        assert svc.config["email"]["password"] == "env-smtp-secret"
        assert svc.config["slack"]["webhook_url"] == "https://hooks.slack.com/services/ENV"
        assert svc.config["webhook"]["headers"]["Authorization"] == "Bearer env-webhook-token"
        assert "authorization" not in svc.config["webhook"]["headers"]
        assert "Proxy-Authorization" not in svc.config["webhook"]["headers"]
        assert "X-API-Key" not in svc.config["webhook"]["headers"]
        assert svc.config["webhook"]["headers"]["Content-Type"] == "application/json"


class TestWebhookRequestSafety:
    """Ensure webhook network requests keep SSRF protections at send time."""

    def test_restricted_resolver_rejects_private_ip_at_connection_time(self):
        async def _resolve_private_ip():
            resolver = RestrictedWebhookResolver(lambda ip: ip == "10.0.0.1")
            try:
                await resolver.resolve("10.0.0.1", 443)
            finally:
                await resolver.close()

        with pytest.raises(ValueError, match="private or restricted"):
            asyncio.run(_resolve_private_ip())

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return None

        class FakeSession:
            def __init__(self, **kwargs):
                captured["session_kwargs"] = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["post_kwargs"] = kwargs
                return FakeResponse()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc._webhook_connector = lambda: object()
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        msg = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        post_kwargs = captured["post_kwargs"]
        assert isinstance(post_kwargs, dict)
        assert post_kwargs["allow_redirects"] is False


class TestEmailAttachmentValidation:
    """Ensure email attachments cannot read arbitrary filesystem paths."""

    def test_resolves_attachment_inside_configured_directory(self, tmp_path):
        attachment_dir = tmp_path / "attachments"
        attachment_dir.mkdir()
        attachment = attachment_dir / "report.txt"
        attachment.write_text("ok")

        svc = EnhancedNotificationService()
        svc.config["email"]["attachment_directory"] = str(attachment_dir)

        assert svc._resolve_attachment_path("report.txt") == attachment.resolve()

    def test_rejects_attachment_outside_configured_directory(self, tmp_path):
        attachment_dir = tmp_path / "attachments"
        attachment_dir.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("secret")

        svc = EnhancedNotificationService()
        svc.config["email"]["attachment_directory"] = str(attachment_dir)

        with pytest.raises(ValueError, match="outside"):
            svc._resolve_attachment_path(str(secret))
