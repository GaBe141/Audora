"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

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


class TestNotificationTransportHardening:
    """Outbound channels must not follow redirects or send SMTP auth in cleartext."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Test",
            content="Hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        response = MagicMock()
        response.status = 200
        response.__aenter__.return_value = response
        response.__aexit__.return_value = False

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = False

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_slack(self._message()))

        assert result["success"] is True
        assert session.post.call_args.kwargs.get("allow_redirects") is False

    def test_discord_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        response = MagicMock()
        response.status = 302
        response.__aenter__.return_value = response
        response.__aexit__.return_value = False

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = False

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/discord"),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_discord(self._message()))

        assert result["success"] is False
        assert "Redirect" in result["error"]
        assert session.post.call_args.kwargs.get("allow_redirects") is False

    def test_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        response = MagicMock()
        response.status = 200
        response.__aenter__.return_value = response
        response.__aexit__.return_value = False

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = False

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert session.post.call_args.kwargs.get("allow_redirects") is False

    def test_smtp_auth_requires_tls(self):
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
        result = asyncio.run(svc._send_email(self._message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_smtp_starttls_uses_default_context(self):
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
        with patch("smtplib.SMTP", return_value=server) as smtp_ctor:
            result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        smtp_ctor.assert_called_once()
        context = server.starttls.call_args.kwargs.get("context")
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_email_headers_strip_crlf(self):
        svc = EnhancedNotificationService()
        assert (
            svc._sanitize_header("Subject\r\nBcc: evil@example.com")
            == "SubjectBcc: evil@example.com"
        )

    def test_attachment_outside_allowlist_rejected(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("nope")
        assert svc._resolve_allowed_attachment(str(outside)) is None

    def test_html_body_escapes_content(self):
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
        server = MagicMock()
        message = NotificationMessage(
            title="Test",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        with patch("smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        html_part = server.send_message.call_args.args[0].get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "alert(1)" in html_part
