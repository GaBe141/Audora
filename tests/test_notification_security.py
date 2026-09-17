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

    def test_rejects_cgnat_and_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.1.10") is True
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        assert svc._is_restricted_ip("::ffff:10.0.0.8") is True


class _FakeAiohttpResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def text(self) -> str:
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeAiohttpSession:
    def __init__(self, captured: dict) -> None:
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    def post(self, url, json=None, headers=None, timeout=None, allow_redirects=True, **kwargs):
        self.captured["url"] = url
        self.captured["allow_redirects"] = allow_redirects
        self.captured["json"] = json
        return _FakeAiohttpResponse(status=200)


def _low_priority_message(*channels: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="hello",
        priority=NotificationPriority.LOW,
        channels=list(channels),
    )


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects to private hosts."""

    def test_slack_disables_redirects(self):
        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        with (
            patch(
                "core.notification_service.aiohttp.ClientSession",
                lambda *args, **kwargs: _FakeAiohttpSession(captured),
            ),
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"
            ),
        ):
            result = asyncio.run(svc._send_slack(_low_priority_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert captured["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        with (
            patch(
                "core.notification_service.aiohttp.ClientSession",
                lambda *args, **kwargs: _FakeAiohttpSession(captured),
            ),
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/discord"
            ),
        ):
            result = asyncio.run(
                svc._send_discord(_low_priority_message(NotificationChannel.DISCORD))
            )
        assert result["success"] is True
        assert captured["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self):
        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        with (
            patch(
                "core.notification_service.aiohttp.ClientSession",
                lambda *args, **kwargs: _FakeAiohttpSession(captured),
            ),
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/custom"
            ),
        ):
            result = asyncio.run(
                svc._send_webhook(_low_priority_message(NotificationChannel.WEBHOOK))
            )
        assert result["success"] is True
        assert captured["allow_redirects"] is False

    def test_slack_rejects_redirect_status(self):
        class RedirectSession(_FakeAiohttpSession):
            def post(self, url, json=None, headers=None, timeout=None, allow_redirects=True, **kwargs):
                super().post(
                    url,
                    json=json,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    **kwargs,
                )
                return _FakeAiohttpResponse(status=302)

        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        with (
            patch(
                "core.notification_service.aiohttp.ClientSession",
                lambda *args, **kwargs: RedirectSession(captured),
            ),
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"
            ),
        ):
            result = asyncio.run(svc._send_slack(_low_priority_message(NotificationChannel.SLACK)))
        assert result["success"] is False
        assert "Redirect" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP credentials must never be sent over plaintext."""

    def test_starttls_uses_default_ssl_context(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def starttls(self, context=None) -> None:
                captured["context"] = context

            def login(self, username, password) -> None:
                captured["login"] = (username, password)

            def send_message(self, msg) -> None:
                captured["msg"] = msg

            def quit(self) -> None:
                return None

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_low_priority_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_refuses_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_low_priority_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_html_body_escapes_untrusted_content(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def starttls(self, context=None) -> None:
                return None

            def login(self, username, password) -> None:
                return None

            def send_message(self, msg) -> None:
                captured["msg"] = msg

            def quit(self) -> None:
                return None

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="xss",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        html_bodies = [
            part.get_payload(decode=True).decode("utf-8")
            for part in captured["msg"].walk()
            if part.get_content_type() == "text/html"
        ]
        assert html_bodies
        assert "<script>" not in html_bodies[0]
        assert "&lt;script&gt;" in html_bodies[0]

    def test_rejects_attachments_outside_project_root(self, tmp_path: Path):
        captured: dict = {}
        outside_dir = tmp_path
        project_root = Path(__file__).resolve().parents[1]
        if outside_dir.resolve().is_relative_to(project_root):
            outside_dir = Path("/tmp")
        secret = outside_dir / "audora-secret-attachment.txt"
        secret.write_text("should-not-attach", encoding="utf-8")

        class FakeSMTP:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def starttls(self, context=None) -> None:
                return None

            def login(self, username, password) -> None:
                return None

            def send_message(self, msg) -> None:
                captured["msg"] = msg

            def quit(self) -> None:
                return None

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="file",
            content="see attached",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
            attachments=[str(secret)],
        )
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert isinstance(captured["msg"], MIMEMultipart)
        filenames = [
            part.get_filename()
            for part in captured["msg"].walk()
            if part.get_filename()
        ]
        assert filenames == []
