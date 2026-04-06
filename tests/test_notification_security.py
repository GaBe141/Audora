"""Security tests for notification security controls."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import EnhancedNotificationService


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


class TestNotificationTransportSecurity:
    """Validate transport-level hardening for notification delivery."""

    def test_email_uses_verified_tls_context_for_starttls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["recipient@example.com"],
                "use_tls": True,
            }
        )
        msg = MagicMock()
        message = type(
            "M",
            (),
            {"title": "t", "content": "c", "priority": msg, "template_vars": None, "attachments": None},
        )()
        message.priority = type("P", (), {"value": "high"})()

        with patch("core.notification_service.smtplib.SMTP") as mock_smtp:
            smtp_instance = mock_smtp.return_value
            result = asyncio.run(svc._send_email(message))  # type: ignore[arg-type]
            assert result["success"] is True
            assert smtp_instance.starttls.called
            starttls_kwargs = smtp_instance.starttls.call_args.kwargs
            assert "context" in starttls_kwargs
            assert isinstance(starttls_kwargs["context"], ssl.SSLContext)

    def test_slack_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/B/X"
        svc._validate_webhook_url = MagicMock(return_value="https://hooks.slack.com/services/T/B/X")

        class _Resp:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        post_mock = MagicMock(return_value=_Resp())

        class _Session:
            def post(self, *args, **kwargs):
                return post_mock(*args, **kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        with patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()):
            message = type(
                "M",
                (),
                {
                    "title": "title",
                    "content": "content",
                    "priority": type("P", (), {"value": "high"})(),
                    "template_vars": None,
                    "data": None,
                },
            )()
            result = asyncio.run(svc._send_slack(message))  # type: ignore[arg-type]
            assert result["success"] is True
            assert post_mock.call_args.kwargs.get("allow_redirects") is False
