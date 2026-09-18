"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**kwargs) -> NotificationMessage:
    defaults = {
        "title": "Test",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.EMAIL],
    }
    defaults.update(kwargs)
    return NotificationMessage(**defaults)


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

    def test_rejects_cgnat_and_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        assert svc._is_restricted_ip("::ffff:10.0.0.1") is True
        assert svc._is_restricted_ip("8.8.8.8") is False
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.1.1/webhook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/webhook")


class TestWebhookRedirectHardening:
    """Outbound webhook posts must not follow or accept redirects."""

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured: list[dict] = []

        class FakeResponse:
            status = 302

            async def text(self) -> str:
                return "moved"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def post(self, _url, **kwargs):
                captured.append(kwargs)
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", FakeSession),
        ):
            result = asyncio.run(svc._send_webhook(_message(channels=[NotificationChannel.WEBHOOK])))

        assert captured
        assert captured[0].get("allow_redirects") is False
        assert result["success"] is False
        assert "redirect" in result["error"].lower()

    def test_slack_and_discord_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        captured: list[dict] = []

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def post(self, _url, **kwargs):
                captured.append(kwargs)
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", FakeSession),
        ):
            slack_result = asyncio.run(
                svc._send_slack(_message(channels=[NotificationChannel.SLACK]))
            )
            discord_result = asyncio.run(
                svc._send_discord(_message(channels=[NotificationChannel.DISCORD]))
            )

        assert slack_result["success"] is True
        assert discord_result["success"] is True
        assert captured
        assert all(call.get("allow_redirects") is False for call in captured)


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS before authentication."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["ops@example.com"]
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "secret"
        svc.config["email"]["use_tls"] = False
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["ops@example.com"]
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "secret"
        svc.config["email"]["use_tls"] = True

        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["tls_context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(_message(content="<script>alert(1)</script>\nnext"))
            )

        assert result["success"] is True
        context = captured["tls_context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert captured["login"] == ("user", "secret")
        msg = captured["msg"]
        assert isinstance(msg, MIMEMultipart)
        html_parts = [part for part in msg.walk() if part.get_content_type() == "text/html"]
        assert html_parts
        html_body = html_parts[0].get_payload()
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body


class TestEmailAttachmentSandbox:
    """Email attachments must stay inside the project root."""

    def test_rejects_attachment_outside_project_root(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        assert svc._safe_attachment_path(str(outside)) is None

    def test_allows_attachment_inside_project_root(self):
        svc = EnhancedNotificationService()
        readme = Path(__file__).resolve().parent.parent / "README.md"
        assert svc._safe_attachment_path(str(readme)) == readme.resolve()
