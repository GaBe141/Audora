"""Security tests for notification webhook URL validation."""

import asyncio
import json
import ssl

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
            svc._validate_webhook_url("https://user:password@example.com/webhook")


class TestNotificationSecretPersistence:
    """Ensure runtime secrets are not written back to JSON config files."""

    def test_save_config_strips_plaintext_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"
        svc.config["sms"]["api_secret"] = "sms-secret"
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_secret" not in saved["sms"]


class TestNotificationTransportSecurity:
    """Validate secure outbound transports for notification channels."""

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, _host, _port):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, _msg):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "secret",
                "recipients": ["ops@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["login"] == ("user", "secret")

    def test_smtp_refuses_plaintext_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "recipients": ["ops@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_webhook_sends_without_following_redirects(self, monkeypatch):
        calls = []

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            def post(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False


class TestEmailAttachmentSecurity:
    """Validate attachment path allowlisting."""

    def test_attachment_must_be_inside_configured_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "attachments"
        allowed_dir.mkdir()
        allowed_file = allowed_dir / "report.txt"
        allowed_file.write_text("ok")
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret")

        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))
        svc = EnhancedNotificationService()

        assert svc._resolve_attachment_path(str(allowed_file)) == allowed_file.resolve()
        assert svc._resolve_attachment_path(str(outside_file)) is None
