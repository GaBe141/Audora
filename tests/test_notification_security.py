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


class TestWebhookRedirectHandling:
    """Ensure webhook channels do not follow redirects after validation."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        calls = self._patch_client_session(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_webhook(self._message([NotificationChannel.WEBHOOK])))

        assert result["success"] is True
        assert calls[0]["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        calls = self._patch_client_session(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_slack(self._message([NotificationChannel.SLACK])))

        assert result["success"] is True
        assert calls[0]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        calls = self._patch_client_session(monkeypatch, status=204)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_discord(self._message([NotificationChannel.DISCORD])))

        assert result["success"] is True
        assert calls[0]["allow_redirects"] is False

    def _message(self, channels):
        return NotificationMessage(
            title="Security test",
            content="Webhook redirect test",
            priority=NotificationPriority.HIGH,
            channels=channels,
        )

    def _patch_client_session(self, monkeypatch, status=200):
        calls = []

        class FakeResponse:
            def __init__(self, response_status):
                self.status = response_status

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                calls.append(kwargs)
                return FakeResponse(status)

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        return calls


class TestEmailTransportSecurity:
    """Validate SMTP credentials only travel over verified TLS."""

    def test_rejects_plaintext_smtp_auth(self, monkeypatch):
        smtp = self._patch_smtp(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "use_tls": False,
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.com"],
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
        assert smtp.instances[0].logged_in is False

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        smtp = self._patch_smtp(monkeypatch)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "use_tls": True,
                "username": "user",
                "password": "password",
                "recipients": ["alerts@example.com"],
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is True
        context = smtp.instances[0].tls_context
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def _message(self):
        return NotificationMessage(
            title="Security test",
            content="<script>alert('escaped')</script>",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.EMAIL],
        )

    def _patch_smtp(self, monkeypatch):
        class FakeSMTP:
            instances = []

            def __init__(self, *args, **kwargs):
                self.tls_context = None
                self.logged_in = False
                self.sent = False
                FakeSMTP.instances.append(self)

            def starttls(self, context=None):
                self.tls_context = context

            def login(self, username, password):
                self.logged_in = True

            def send_message(self, msg):
                self.sent = True

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        return FakeSMTP
