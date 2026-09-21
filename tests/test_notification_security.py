"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import patch

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

    def test_rejects_internal_suffix_without_dns(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://metadata.google.internal/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookPosting:
    """Outbound webhook HTTP behavior."""

    def test_post_json_disables_redirects(self):
        recorded: dict = {}

        class FakeResp:
            status = 204

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                recorded["url"] = url
                recorded.update(kwargs)
                return FakeResp()

        with patch("core.notification_service.aiohttp.ClientSession", FakeSession):
            svc = EnhancedNotificationService()
            status, body = asyncio.run(svc._post_json("https://example.com/hook", {"ok": True}))

        assert status == 204
        assert body == "ok"
        assert recorded.get("allow_redirects") is False


class TestSmtpTls:
    """SMTP delivery must use verified TLS."""

    def test_starttls_uses_verified_context(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                captured["host"] = host
                captured["timeout"] = timeout

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

            def close(self):
                captured["close"] = True

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            svc = EnhancedNotificationService()
            svc._deliver_smtp(
                {
                    "smtp_server": "smtp.example.com",
                    "port": 587,
                    "use_tls": True,
                    "username": "user",
                    "password": "secret",
                },
                MIMEMultipart(),
            )

        assert captured["timeout"] == 30
        assert captured["sent"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_refuses_auth_without_tls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="unencrypted SMTP"):
            svc._deliver_smtp(
                {
                    "smtp_server": "smtp.example.com",
                    "port": 587,
                    "use_tls": False,
                    "username": "user",
                    "password": "secret",
                },
                MIMEMultipart(),
            )


class TestEmailAttachmentPaths:
    """Email attachments must stay under data/."""

    def test_rejects_attachment_outside_data(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data").mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("nope")
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(secret)) is None
        assert svc._safe_attachment_path("../secret.txt") is None

    def test_allows_attachment_in_data(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        allowed = data_dir / "report.txt"
        allowed.write_text("ok")
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(allowed)) == allowed.resolve()
        assert svc._safe_attachment_path("report.txt") == allowed.resolve()
