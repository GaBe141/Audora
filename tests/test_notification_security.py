"""Security tests for notification webhook URL validation."""

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
        "channels": [NotificationChannel.WEBHOOK],
    }
    defaults.update(kwargs)
    return NotificationMessage(**defaults)


class _FakeResponse:
    def __init__(self, status: int, text: str = "ok"):
        self.status = status
        self._text = text

    async def text(self) -> str:
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.post_calls: list[dict] = []

    def post(self, *args, **kwargs):
        self.post_calls.append({"args": args, "kwargs": kwargs})
        return self.response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


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


class TestWebhookTransportHardening:
    """Outbound notification HTTP clients must not follow redirects."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake = _FakeSession(_FakeResponse(200))
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("aiohttp.ClientSession", return_value=fake),
        ):
            result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert fake.post_calls[0]["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake = _FakeSession(_FakeResponse(302, text="https://169.254.169.254/"))
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("aiohttp.ClientSession", return_value=fake),
        ):
            result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        fake = _FakeSession(_FakeResponse(200))
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://hooks.slack.com/services/test"),
            patch("aiohttp.ClientSession", return_value=fake),
        ):
            result = asyncio.run(
                svc._send_slack(_message(channels=[NotificationChannel.SLACK]))
            )
        assert result["success"] is True
        assert fake.post_calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        fake = _FakeSession(_FakeResponse(204))
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://discord.com/api/webhooks/test"
            ),
            patch("aiohttp.ClientSession", return_value=fake),
        ):
            result = asyncio.run(
                svc._send_discord(_message(channels=[NotificationChannel.DISCORD]))
            )
        assert result["success"] is True
        assert fake.post_calls[0]["kwargs"]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in the clear."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

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
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_body_escapes_untrusted_content(self):
        captured: dict[str, MIMEMultipart] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                return None

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        payload = _message(
            channels=[NotificationChannel.EMAIL],
            content="<script>alert(1)</script>",
        )
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(payload))
        assert result["success"] is True
        html_part = captured["msg"].get_payload()[1].get_payload(decode=True).decode("utf-8")
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part


class TestEmailAttachmentAllowlist:
    """Email attachments must not read arbitrary filesystem paths."""

    def test_rejects_path_outside_allowlisted_directories(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("classified", encoding="utf-8")
        svc = EnhancedNotificationService()
        assert svc._is_allowed_attachment(str(secret)) is False

    def test_allows_file_under_data_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        data_dir = Path("data")
        data_dir.mkdir()
        allowed = data_dir / "report.txt"
        allowed.write_text("ok", encoding="utf-8")
        svc = EnhancedNotificationService()
        assert svc._is_allowed_attachment(str(allowed)) is True
