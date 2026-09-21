"""Security tests for notification webhook URL validation."""

import asyncio
import socket
from email.mime.multipart import MIMEMultipart

import aiohttp
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

    def test_rejects_localhost_suffixes(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://attacker.localhost/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_credentials_and_obfuscated_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://2130706433/hook")
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://0177.0.0.1/hook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook")

    def test_webhook_post_pins_address_and_blocks_redirects(self, monkeypatch):
        calls: dict[str, object] = {}

        class _FakeResponse:
            status = 302

            async def text(self) -> str:
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class _FakeSession:
            def __init__(self, *_args, **kwargs):
                calls["trust_env"] = kwargs.get("trust_env")
                calls["connector"] = kwargs.get("connector")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                calls["url"] = url
                calls["allow_redirects"] = kwargs.get("allow_redirects")
                return _FakeResponse()

        def _fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]

        monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example/notify"
        message = NotificationMessage(
            title="Test",
            content="Hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is False
        assert result["error"] == "Webhook redirect was blocked"
        assert calls["allow_redirects"] is False
        assert calls["trust_env"] is False
        resolver = calls["connector"]._resolver
        assert resolver._addresses == ("1.1.1.1",)


class TestEmailHardening:
    """SMTP and attachment safeguards."""

    def test_strips_header_injection(self):
        svc = EnhancedNotificationService()
        assert "\n" not in svc._sanitize_header("Subject\r\nBcc: attacker@example.com")

    def test_rejects_attachment_outside_data_dir(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("secret")
        assert svc._safe_attachment_path(str(secret)) is None

    def test_html_body_is_escaped(self, monkeypatch):
        sent: dict[str, MIMEMultipart] = {}

        class _FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                return None

            def ehlo(self):
                return None

            def starttls(self, context=None):
                sent["context"] = context
                return None

            def login(self, *_args):
                return None

            def send_message(self, msg):
                sent["msg"] = msg

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        svc.config["email"]["username"] = ""
        svc.config["email"]["password"] = ""
        message = NotificationMessage(
            title="Hello\r\nBcc: bad@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        html_part = sent["msg"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
        assert "\n" not in sent["msg"]["Subject"]
        assert "\r" not in sent["msg"]["Subject"]
        assert "Bcc" not in sent["msg"]
        assert sent["context"] is not None
