"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="payload",
        priority=NotificationPriority.LOW,
        channels=[channel],
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


class TestWebhookRedirectHardening:
    """Outbound webhook POSTs must not follow redirects to internal hosts."""

    def test_slack_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        response = MagicMock()
        response.status = 302
        session = MagicMock()
        session.post.return_value.__aenter__.return_value = response
        session_cm = MagicMock()
        session_cm.__aenter__.return_value = session

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_discord_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        response = MagicMock()
        response.status = 301
        session = MagicMock()
        session.post.return_value.__aenter__.return_value = response
        session_cm = MagicMock()
        session_cm.__aenter__.return_value = session

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value=svc.config["discord"]["webhook_url"]
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        response = MagicMock()
        response.status = 307
        session = MagicMock()
        session.post.return_value.__aenter__.return_value = response
        session_cm = MagicMock()
        session_cm.__aenter__.return_value = session

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
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
        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
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
            patch("core.notification_service.smtplib.SMTP", return_value=server) as smtp_ctor,
            patch("core.notification_service.ssl.create_default_context") as create_ctx,
        ):
            context = MagicMock()
            create_ctx.return_value = context
            result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        smtp_ctor.assert_called_once()
        server.starttls.assert_called_once()
        assert server.starttls.call_args.kwargs["context"] is context
        server.login.assert_called_once_with("user", "secret")

    def test_sanitizes_header_newlines(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Subject\r\nBcc: attacker@example.com") == (
            "SubjectBcc: attacker@example.com"
        )

    def test_rejects_attachments_outside_allowed_roots(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secrets.txt"
        outside.write_text("classified", encoding="utf-8")
        assert svc._is_allowed_attachment_path(outside) is False
