"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from pathlib import Path
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestEmailTransportSecurity:
    """SMTP must use verified TLS before transmitting credentials."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Alert",
                    content="body",
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
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp) as smtp_cls,
            patch(
                "core.notification_service.ssl.create_default_context",
                wraps=ssl.create_default_context,
            ) as create_ctx,
        ):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp_cls.assert_called_once()
        create_ctx.assert_called_once()
        smtp.starttls.assert_called_once()
        context = smtp.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_sanitizes_email_headers(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Subject\r\nBcc: attacker@example.com") == "SubjectBcc: attacker@example.com"

    def test_rejects_attachments_outside_allowed_roots(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.chdir(tmp_path)
        outside = Path("/etc/passwd")
        assert svc._is_allowed_attachment_path(outside) is False
        allowed = tmp_path / "report.txt"
        allowed.write_text("ok")
        assert svc._is_allowed_attachment_path(allowed) is True


class TestWebhookRedirectRejection:
    """Outbound webhooks must not follow redirects to private hosts."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/abc"
        response = MagicMock()
        response.status = 200
        post_cm = MagicMock()
        post_cm.__aenter__ = AsyncMock(return_value=response)
        post_cm.__aexit__ = AsyncMock(return_value=None)
        session = MagicMock()
        session.post.return_value = post_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://hooks.slack.test/abc"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(
                svc._send_slack(
                    NotificationMessage(
                        title="Slack",
                        content="hi",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.SLACK],
                    )
                )
            )
        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.test/abc"
        response = MagicMock()
        response.status = 302
        response.text = AsyncMock(return_value="redirect")
        post_cm = MagicMock()
        post_cm.__aenter__ = AsyncMock(return_value=response)
        post_cm.__aexit__ = AsyncMock(return_value=None)
        session = MagicMock()
        session.post.return_value = post_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.test/abc"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(
                svc._send_webhook(
                    NotificationMessage(
                        title="Hook",
                        content="hi",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.WEBHOOK],
                    )
                )
            )
        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs["allow_redirects"] is False
