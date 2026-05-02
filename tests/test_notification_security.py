"""Security tests for notification transport hardening."""

import json
import asyncio

import aiohttp
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    last_post_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.__class__.last_post_kwargs = kwargs
        return _FakeResponse()


class TestWebhookDeliverySecurity:
    """Validate outbound delivery does not weaken URL protections."""

    def setup_method(self):
        _FakeSession.last_post_kwargs = None

    @pytest.mark.parametrize(
        ("channel_name", "config_key"),
        [
            ("SLACK", "slack"),
            ("DISCORD", "discord"),
            ("WEBHOOK", "webhook"),
        ],
    )
    def test_webhook_channels_disable_redirects(self, monkeypatch, channel_name, config_key):
        monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        if config_key == "webhook":
            svc.config[config_key]["url"] = "https://example.com/hook"
        else:
            svc.config[config_key]["webhook_url"] = "https://example.com/hook"

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[getattr(NotificationChannel, channel_name)],
        )

        asyncio.run(svc.send_notification(message))

        assert _FakeSession.last_post_kwargs is not None
        assert _FakeSession.last_post_kwargs["allow_redirects"] is False


class TestEmailSecurity:
    """Validate SMTP credentials are never sent over plaintext."""

    def test_rejects_smtp_auth_without_tls(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "mail.example.com",
                "recipients": ["user@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "pass",
            }
        )

        def fail_smtp(*args, **kwargs):
            raise AssertionError("SMTP connection should not be opened")

        monkeypatch.setattr("smtplib.SMTP", fail_smtp)
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]


def test_save_config_uses_restrictive_permissions(tmp_path):
    svc = EnhancedNotificationService()
    config_path = tmp_path / "notification_config.json"

    svc.save_config(str(config_path))

    assert config_path.stat().st_mode & 0o777 == 0o600
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert "email" in saved
