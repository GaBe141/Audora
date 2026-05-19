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
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportSecurity:
    """Validate outbound webhook transport hardening."""

    def test_slack_post_disables_redirects(self, monkeypatch):
        captured = {}

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class FakeSession:
            def __init__(self, *args, **kwargs):
                captured["session_kwargs"] = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured["post_url"] = url
                captured["post_kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url
        svc.config["slack"]["webhook_url"] = "https://example.com/webhook"
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(msg))

        assert result["success"] is True
        assert captured["post_kwargs"]["allow_redirects"] is False
        assert captured["session_kwargs"]["timeout"].total == 30


class TestEmailSecurity:
    """Validate secure email delivery behavior."""

    def test_plaintext_smtp_auth_is_rejected(self, monkeypatch):
        def fail_smtp(*args, **kwargs):
            raise AssertionError("SMTP should not be opened before TLS auth validation")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fail_smtp)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def starttls(self, context=None):
                captured["context"] = context

            def send_message(self, msg):
                captured["message"] = msg

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "use_tls": True,
            }
        )
        msg = NotificationMessage(
            title="Test",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert "&lt;script&gt;" in captured["message"].as_string()


class TestAttachmentSecurity:
    """Validate attachment path containment."""

    def test_attachment_must_stay_under_configured_directory(self, tmp_path):
        allowed_dir = tmp_path / "attachments"
        allowed_dir.mkdir()
        allowed = allowed_dir / "report.txt"
        allowed.write_text("safe", encoding="utf-8")
        secret = tmp_path / "secret.txt"
        secret.write_text("secret", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["attachment_dir"] = str(allowed_dir)

        assert svc._resolve_attachment_path(str(allowed)) == allowed.resolve()
        assert svc._resolve_attachment_path(str(secret)) is None


class TestConfigPersistenceSecurity:
    """Validate persisted notification config omits secret values."""

    def test_save_config_strips_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://example.com/slack-secret"
        svc.config["webhook"]["url"] = "https://example.com/custom-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        path = tmp_path / "notification_config.json"

        svc.save_config(str(path))

        saved = json.loads(path.read_text(encoding="utf-8"))
        serialized = json.dumps(saved)
        assert "smtp-secret" not in serialized
        assert "slack-secret" not in serialized
        assert "custom-secret" not in serialized
        assert "Bearer secret" not in serialized
