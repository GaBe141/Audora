"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

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

    def test_rejects_cgnat_and_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        assert svc._is_restricted_ip("::ffff:10.1.2.3") is True
        assert svc._is_restricted_ip("8.8.8.8") is False
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.1.1/hook")


class TestWebhookRedirects:
    """Outbound webhook POSTs must not follow redirects."""

    def test_custom_webhook_refuses_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://93.184.216.34/hook"

        response = MagicMock()
        response.status = 302
        response.text = AsyncMock(return_value="redirect")
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(
                svc._send_webhook(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.WEBHOOK],
                    )
                )
            )

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs.get("allow_redirects") is False


class TestSmtpTransportSecurity:
    """SMTP auth must not run over plaintext."""

    def test_refuses_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="t",
                    content="<script>alert(1)</script>",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )
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
        server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(
                svc._send_email(
                    NotificationMessage(
                        title="t",
                        content="<b>hi</b>",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )
        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        payload = server.send_message.call_args.args[0].as_string()
        assert "&lt;b&gt;hi&lt;/b&gt;" in payload
        html_part = payload.split("Content-Type: text/html", 1)[-1]
        assert "<b>hi</b>" not in html_part


class TestAttachmentConfinement:
    """Email attachments must stay inside the project root."""

    def test_rejects_path_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outsider = tmp_path / "secret.txt"
        outsider.write_text("nope")
        assert svc._resolve_attachment_path(str(outsider)) is None
