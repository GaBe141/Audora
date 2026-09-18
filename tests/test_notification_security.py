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
        title="Test",
        content="Body",
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
    """Outbound webhook posts must not follow redirects."""

    def _patch_post(self, monkeypatch, status=200):
        captured: dict = {}

        class FakeResponse:
            def __init__(self, status_code: int):
                self.status = status_code

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResponse(status)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: FakeSession(),
        )
        return captured

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_post(monkeypatch)

        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_post(monkeypatch)

        result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        captured = self._patch_post(monkeypatch, status=204)

        result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_rejects_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        self._patch_post(monkeypatch, status=302)

        result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is False
        assert "Redirect" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in the clear."""

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

        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["subject"] = msg["Subject"]
                captured["parts"] = {
                    part.get_content_type(): part.get_payload() for part in msg.walk()
                }

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
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

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Alert\nBcc: attacker@example.com",
                    content="<script>alert(1)</script>",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert captured["subject"] == "AlertBcc: attacker@example.com"
        html_part = captured["parts"]["text/html"]
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
