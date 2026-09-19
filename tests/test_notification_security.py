"""Security tests for notification webhook URL validation."""

import asyncio
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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


def _sample_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="Body",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects to private hosts."""

    def test_slack_post_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/abc"
        captured: dict = {}

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return DummyResponse()

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)

        result = asyncio.run(svc._send_slack(_sample_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_discord_and_custom_webhook_reject_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.test/hook"
        svc.config["webhook"]["url"] = "https://example.test/hook"

        class RedirectResponse:
            status = 302

            async def text(self):
                return "moved"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                assert kwargs.get("allow_redirects") is False
                return RedirectResponse()

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **_: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)

        discord_result = asyncio.run(
            svc._send_discord(_sample_message(NotificationChannel.DISCORD))
        )
        webhook_result = asyncio.run(
            svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK))
        )
        assert discord_result["success"] is False
        assert webhook_result["success"] is False
        assert "Redirect" in discord_result["error"]
        assert "Redirect" in webhook_result["error"]


class TestEmailTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_refuses_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "recipients": ["user@example.com"],
            "username": "user",
            "password": "secret",
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "from_address": "music@example.com",
            "recipients": ["user@example.com"],
            "username": "user",
            "password": "secret",
            "use_tls": True,
        }
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, *args):
                captured["login"] = True

            def send_message(self, msg):
                captured["html"] = msg.as_string()

            def quit(self):
                captured["quit"] = True

            def close(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Alert\nBcc: attacker@example.com",
                    content="<script>alert(1)</script>",
                    priority=NotificationPriority.HIGH,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert not any(line.startswith("Bcc:") for line in captured["html"].splitlines())
        assert "&lt;script&gt;" in captured["html"]

    def test_sanitizes_header_newlines(self):
        svc = EnhancedNotificationService()
        assert "\n" not in svc._sanitize_header_value("Hi\nBcc: evil@example.com")
        assert "\r" not in svc._sanitize_header_value("Hi\rTo: evil@example.com")

    def test_rejects_attachment_outside_allowed_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("classified")
        assert svc._resolve_attachment_path(str(secret)) is None
