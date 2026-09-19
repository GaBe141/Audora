"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationTransportHardening:
    """Outbound email/webhooks must not follow redirects or skip TLS checks."""

    def test_sanitize_header_strips_crlf(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Subject\r\nBcc: attacker@example.com") == "SubjectBcc: attacker@example.com"

    def test_attachment_outside_allowed_dirs_rejected(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("nope")
        assert svc._is_allowed_attachment(str(secret)) is False

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "music@example.com",
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
            "username": "",
            "password": "",
            "from_address": "music@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        server = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server) as smtp_cls,
            patch(
                "core.notification_service.ssl.create_default_context",
                wraps=ssl.create_default_context,
            ) as make_ctx,
        ):
            result = asyncio.run(
                svc._send_email(
                    NotificationMessage(
                        title="Alert",
                        content="<script>alert(1)</script>",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )
        assert result["success"] is True
        smtp_cls.assert_called_once()
        server.starttls.assert_called_once()
        kwargs = server.starttls.call_args.kwargs
        assert "context" in kwargs
        assert isinstance(kwargs["context"], ssl.SSLContext)
        make_ctx.assert_called()

    def test_webhook_posts_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        class _Response:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        captured: list[dict] = []

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured.append({"url": url, **kwargs})
                return _Response()

        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        async def _send_all():
            await svc._send_webhook(message)
            await svc._send_slack(message)
            await svc._send_discord(message)

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_k: url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()),
        ):
            asyncio.run(_send_all())

        assert captured
        assert all(item.get("allow_redirects") is False for item in captured)
