"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _sample_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="hello <script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class _FakeResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.post_calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return _FakeResponse(status=self.status)


class _FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.starttls_kwargs = None
        self.logged_in = False

    def starttls(self, *args, **kwargs):
        self.starttls_kwargs = kwargs

    def login(self, *args):
        self.logged_in = True

    def send_message(self, msg):
        self.msg = msg

    def quit(self):
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportHardening:
    """Outbound webhook posts must not follow redirects."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        fake_session = _FakeSession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_slack(_sample_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert fake_session.post_calls
        assert fake_session.post_calls[0][1]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        fake_session = _FakeSession(status=204)
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://discord.com/api/webhooks/test"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_discord(_sample_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert fake_session.post_calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake_session = _FakeSession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is True
        assert fake_session.post_calls[0][1]["allow_redirects"] is False

    def test_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake_session = _FakeSession(status=302)
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is False
        assert "redirects are not allowed" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP authentication must use verified TLS."""

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
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
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
        fake_smtp = _FakeSMTP()
        with patch("core.notification_service.smtplib.SMTP", return_value=fake_smtp):
            result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        assert fake_smtp.starttls_kwargs is not None
        context = fake_smtp.starttls_kwargs.get("context")
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert fake_smtp.logged_in is True

    def test_html_email_escapes_content(self):
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
        fake_smtp = _FakeSMTP()
        with patch("core.notification_service.smtplib.SMTP", return_value=fake_smtp):
            asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        html_part = fake_smtp.msg.get_payload()[1].get_payload(decode=True).decode("utf-8")
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part


class TestAttachmentPathAllowlist:
    def test_rejects_paths_outside_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data").mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_text("nope")
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(outside)) is None

    def test_accepts_files_inside_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        inside = data_dir / "report.txt"
        inside.write_text("ok")
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(inside)) == inside.resolve()
