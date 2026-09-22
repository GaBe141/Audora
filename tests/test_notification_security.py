"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

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

    def test_rejects_loopback_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)

    def test_rejects_link_local_metadata_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_rejects_ipv4_mapped_loopback_and_obfuscated_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://2130706433/hook")
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")

    def test_rejects_metadata_and_localhost_suffixes(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Metadata"):
            svc._validate_webhook_url("https://metadata.google.internal/compute")
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://app.localhost/hook")

    def test_post_pins_addresses_and_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        url = "https://example.com/hook"
        svc._pinned_webhook_ips[url] = ["93.184.216.34"]
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs):
                captured["trust_env"] = kwargs.get("trust_env")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, posted_url, **kwargs):
                captured["url"] = posted_url
                captured["allow_redirects"] = kwargs.get("allow_redirects")
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        status, body = asyncio.run(svc._post_webhook(url, {"ok": True}))
        assert status == 200
        assert body == "ok"
        assert captured["trust_env"] is False
        assert captured["allow_redirects"] is False
        assert captured["url"] == url

    def test_email_uses_verified_tls_and_strips_header_injection(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["listener@example.com"],
        }
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["context"] = context

            def send_message(self, msg):
                captured["subject"] = msg["Subject"]
                html_part = msg.get_payload()[1].get_payload()
                captured["html"] = html_part

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        message = NotificationMessage(
            title="Hello\r\nBcc: attacker@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert "\n" not in str(captured["subject"])
        assert "\r" not in str(captured["subject"])
        assert "<script>" not in str(captured["html"])
        assert "&lt;script&gt;" in str(captured["html"])

    def test_email_rejects_attachment_outside_project(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["listener@example.com"],
        }
        message = NotificationMessage(
            title="Report",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
            attachments=["/etc/passwd"],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
