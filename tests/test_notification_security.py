"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from pathlib import Path
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

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:token@example.com/webhook")


class TestEmailHardening:
    """Header injection, HTML escaping, TLS, and attachment confinement."""

    def test_strips_crlf_from_headers(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header_value("Subject\r\nBcc: attacker@evil.com") == (
            "SubjectBcc: attacker@evil.com"
        )

    def test_html_email_escapes_markup(self):
        svc = EnhancedNotificationService()
        body = svc._render_html_email('<script>alert("xss")</script>\nnext')
        assert "<script>" not in body
        assert "&lt;script&gt;" in body
        assert "<br>" in body

    def test_rejects_attachment_outside_allowed_dirs(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        assert svc._safe_attachment_path(str(outside)) is None

    def test_allows_attachment_under_data_dir(self):
        svc = EnhancedNotificationService()
        data_root = Path(__file__).resolve().parent.parent / "data"
        data_root.mkdir(parents=True, exist_ok=True)
        allowed = data_root / "notif_security_attachment.txt"
        allowed.write_text("ok", encoding="utf-8")
        try:
            assert svc._safe_attachment_path(str(allowed)) == allowed.resolve()
        finally:
            allowed.unlink(missing_ok=True)

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="hi",
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
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="hi",
            content="<b>body</b>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp),
            patch(
                "core.notification_service.ssl.create_default_context",
                wraps=ssl.create_default_context,
            ) as ctx_factory,
        ):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp.starttls.assert_called_once()
        assert ctx_factory.called
        context_arg = smtp.starttls.call_args.kwargs.get("context")
        assert context_arg is not None


class TestWebhookRedirectsDisabled:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        message = NotificationMessage(
            title="hi",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def __init__(self):
                self.post_kwargs = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                self.post_kwargs = kwargs
                return FakeResponse()

        fake_session = FakeSession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert fake_session.post_kwargs["allow_redirects"] is False
