"""Security tests for notification webhook URL validation and transport hardening."""

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

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_cgnat_shared_address_space(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransport:
    """Outbound webhook POSTs must not follow redirects."""

    def test_slack_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        captured: dict = {}

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResponse()

        message = NotificationMessage(
            title="test",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_slack(message))

        assert captured["kwargs"]["allow_redirects"] is False
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]


class TestSmtpTransport:
    """SMTP must use verified TLS before authentication."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="alert",
            content="body",
            priority=NotificationPriority.LOW,
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
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="alert",
            content="<b>not html</b>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp) as smtp_cls:
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp_cls.assert_called_once()
        kwargs = smtp.starttls.call_args.kwargs
        context = kwargs.get("context")
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        smtp.login.assert_called_once_with("user", "secret")

        sent_message = smtp.send_message.call_args.args[0]
        assert isinstance(sent_message, MIMEMultipart)
        html_part = sent_message.get_payload()[1].get_payload(decode=True).decode("utf-8")
        assert "&lt;b&gt;not html&lt;/b&gt;" in html_part
        assert "<b>not html</b>" not in html_part

    def test_rejects_attachments_outside_project_root(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        outside = tmp_path / "secret.txt"
        outside.write_text("should-not-attach", encoding="utf-8")
        message = NotificationMessage(
            title="alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
            attachments=[str(outside)],
        )
        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        sent_message = smtp.send_message.call_args.args[0]
        assert len(sent_message.get_payload()) == 2
