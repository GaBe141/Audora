"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import patch

import pytest

from core import notification_service as ns
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**overrides):
    defaults = {
        "title": "Test",
        "content": "Hello <script>alert(1)</script>",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.WEBHOOK],
    }
    defaults.update(overrides)
    return NotificationMessage(**defaults)


class _FakeResponse:
    def __init__(self, status: int, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.posts: list[dict] = []

    def post(self, url, **kwargs):
        self.posts.append({"url": url, **kwargs})
        return _FakeResponse(self.status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


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

    def test_rejects_localhost_subdomain(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://app.localhost/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_cgnat_ip_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_private_ip(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.0.0.1]/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransportHardening:
    """Outbound Slack/Discord/webhook posts must not follow redirects."""

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake_session = _FakeSession(status=302)

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert fake_session.posts
        assert fake_session.posts[0]["allow_redirects"] is False
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        fake_session = _FakeSession(status=200)

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_slack(_message()))

        assert fake_session.posts[0]["allow_redirects"] is False
        assert result["success"] is True

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        fake_session = _FakeSession(status=204)

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value=svc.config["discord"]["webhook_url"]
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_discord(_message()))

        assert fake_session.posts[0]["allow_redirects"] is False
        assert result["success"] is True


class TestSmtpTransportSecurity:
    """SMTP credentials must only be sent after verified TLS."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
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
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_validated_ssl_context(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

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

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert captured["login"] == ("user", "secret")

        html_part = None
        assert isinstance(captured["msg"], MIMEMultipart)
        for part in captured["msg"].walk():
            if part.get_content_type() == "text/html":
                html_part = part.get_payload(decode=True).decode()
        assert html_part is not None
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part


class TestAttachmentPathSafety:
    """Email attachments must stay inside the project root."""

    def test_rejects_path_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("nope")
        assert svc._is_safe_attachment_path(str(outside)) is False

    def test_accepts_file_inside_project(self):
        svc = EnhancedNotificationService()
        inside = ns._PROJECT_ROOT / "README.md"
        if inside.exists():
            assert svc._is_safe_attachment_path(str(inside)) is True
        else:
            pytest.skip("README.md is not present in this checkout")
