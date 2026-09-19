"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock, patch

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransportHardening:
    """Outbound webhook POSTs must not follow redirects."""

    def test_slack_discord_and_custom_webhooks_disable_redirects(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        captured: list[dict] = []

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                captured.append(kwargs)
                return FakeResponse()

        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_k: url),
            patch("aiohttp.ClientSession", return_value=FakeSession()),
        ):
            asyncio.run(svc._send_slack(message))
            asyncio.run(svc._send_discord(message))
            asyncio.run(svc._send_webhook(message))

        assert captured
        assert all(kwargs.get("allow_redirects") is False for kwargs in captured)

    def test_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        assert svc._reject_redirect_status(302)["success"] is False
        assert svc._reject_redirect_status(200) is None


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_refuses_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Alert\r\nBcc: attacker@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        fake_server = MagicMock()
        with patch("smtplib.SMTP", return_value=fake_server) as smtp_cls:
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp_cls.assert_called_once()
        context = fake_server.starttls.call_args.kwargs.get("context")
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        sent_message = fake_server.send_message.call_args.args[0]
        assert isinstance(sent_message, MIMEMultipart)
        assert "\r" not in sent_message["Subject"]
        assert "\n" not in sent_message["Subject"]
        html_part = sent_message.get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "alert(1)" in html_part

    def test_attachments_are_confined_to_export_directories(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.chdir(tmp_path)
        outside = tmp_path / "secret.txt"
        outside.write_text("nope")
        allowed_dir = tmp_path / "exports"
        allowed_dir.mkdir()
        allowed = allowed_dir / "report.csv"
        allowed.write_text("ok")

        assert svc._resolve_safe_attachment(str(outside)) is None
        assert svc._resolve_safe_attachment(str(allowed)) == allowed.resolve()
