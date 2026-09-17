"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="body",
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_cgnat_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_private_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [(None, None, proto, "", ("::ffff:10.0.0.1", port))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://mapped.example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_allows_public_resolved_host(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [(None, None, proto, "", ("1.1.1.1", port))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
        url = "https://hooks.example.com/webhook"
        assert svc._validate_webhook_url(url) == url


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def _patch_session(self, monkeypatch, status: int = 200):
        posted: dict = {}

        class FakeResponse:
            def __init__(self):
                self.status = status

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

            def post(self, url, json=None, headers=None, timeout=None, allow_redirects=True):
                posted["url"] = url
                posted["allow_redirects"] = allow_redirects
                posted["json"] = json
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        return posted

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.test/abc"
        posted = self._patch_session(monkeypatch)
        result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert posted["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        svc.config["discord"]["webhook_url"] = "https://discord.test/api/webhooks/1"
        posted = self._patch_session(monkeypatch, status=204)
        result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert posted["allow_redirects"] is False

    def test_custom_webhook_rejects_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        svc.config["webhook"]["url"] = "https://example.com/hook"
        posted = self._patch_session(monkeypatch, status=302)
        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is False
        assert "Redirects" in result["error"]
        assert posted["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS and must not auth over plaintext."""

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
        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
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
        calls: dict = {}

        class FakeSMTP:
            def __init__(self, host, port):
                calls["host"] = host
                calls["port"] = port

            def starttls(self, context=None):
                calls["context"] = context

            def login(self, username, password):
                calls["login"] = (username, password)

            def send_message(self, msg):
                calls["sent"] = True

            def quit(self):
                calls["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        assert isinstance(calls["context"], ssl.SSLContext)
        assert calls["context"].check_hostname is True
        assert calls["context"].verify_mode == ssl.CERT_REQUIRED
        assert calls["login"] == ("user", "secret")


class TestEmailAttachmentAndHtmlSafety:
    def test_html_email_escapes_content(self, monkeypatch):
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
        captured = {}

        class FakeSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self, context=None):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        msg = NotificationMessage(
            title="alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is True
        html_part = captured["msg"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_rejects_attachments_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        assert svc._is_safe_attachment_path(str(outside)) is False

    def test_allows_attachments_inside_project(self):
        from pathlib import Path

        import core.notification_service as ns

        svc = EnhancedNotificationService()
        inside = Path(ns._PROJECT_ROOT) / "README.md"
        assert inside.is_file()
        assert svc._is_safe_attachment_path(str(inside)) is True
