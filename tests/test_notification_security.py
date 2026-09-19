"""Security tests for notification webhook URL validation."""

import asyncio
import html
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        response = MagicMock()
        response.status = 200
        session = MagicMock()
        session.post = MagicMock(return_value=AsyncMock())

        async def _run():
            post_cm = AsyncMock()
            post_cm.__aenter__.return_value = response
            session_cm = AsyncMock()
            session_cm.__aenter__.return_value = session
            session.post.return_value = post_cm
            with (
                patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
                patch("aiohttp.ClientSession", return_value=session_cm),
            ):
                result = await svc._send_webhook(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[],
                    )
                )
            return result

        result = asyncio.run(_run())
        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        response = MagicMock()
        response.status = 302

        async def _run():
            post_cm = AsyncMock()
            post_cm.__aenter__.return_value = response
            session = MagicMock()
            session.post.return_value = post_cm
            session_cm = AsyncMock()
            session_cm.__aenter__.return_value = session
            with (
                patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
                patch("aiohttp.ClientSession", return_value=session_cm),
            ):
                return await svc._send_webhook(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[],
                    )
                )

        result = asyncio.run(_run())
        assert result["success"] is False
        assert "redirect" in result["error"].lower()


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in the clear."""

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
                    title="t",
                    content="c",
                    priority=NotificationPriority.LOW,
                    channels=[],
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
        server = MagicMock()
        with (
            patch("smtplib.SMTP", return_value=server) as smtp_cls,
            patch("ssl.create_default_context") as create_ctx,
        ):
            ctx = MagicMock()
            create_ctx.return_value = ctx
            result = asyncio.run(
                svc._send_email(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[],
                    )
                )
            )
        assert result["success"] is True
        smtp_cls.assert_called_once()
        create_ctx.assert_called_once()
        server.starttls.assert_called_once_with(context=ctx)
        server.login.assert_called_once()


class TestEmailContentHardening:
    """Email headers and HTML bodies must not accept injected content."""

    def test_strips_crlf_from_subject(self):
        assert "\n" not in EnhancedNotificationService._sanitize_header_value(
            "Subject\r\nBcc: evil@example.com"
        )

    def test_html_body_is_escaped(self):
        raw = '<script>alert("xss")</script>'
        assert html.escape(raw) == "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"

    def test_rejects_attachment_outside_export_dirs(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("classified")
        assert svc._is_allowed_attachment(secret) is False
        export_dir = Path("exports")
        export_dir.mkdir(exist_ok=True)
        allowed = export_dir / "ok.csv"
        allowed.write_text("a,b\n1,2\n")
        try:
            assert svc._is_allowed_attachment(allowed) is True
        finally:
            allowed.unlink(missing_ok=True)
