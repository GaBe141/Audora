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


class TestNotificationTransportSecurity:
    """Validate outbound notification transport hardening."""

    def _message(self, channels=None):
        return NotificationMessage(
            title="Security alert",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=channels or [NotificationChannel.WEBHOOK],
        )

    def _allow_example_dns(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )

    def _install_fake_client_session(self, monkeypatch, captured_posts, *, status=200):
        class FakeResponse:
            def __init__(self):
                self.status = status

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def text(self):
                return "redirect"

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, *args, **kwargs):
                captured_posts.append({"args": args, "kwargs": kwargs})
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        captured_posts = []
        self._install_fake_client_session(monkeypatch, captured_posts)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert captured_posts[0]["kwargs"]["allow_redirects"] is False

    def test_slack_and_discord_disable_redirects(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        captured_posts = []
        self._install_fake_client_session(monkeypatch, captured_posts)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        slack_result = asyncio.run(svc._send_slack(self._message([NotificationChannel.SLACK])))
        discord_result = asyncio.run(svc._send_discord(self._message([NotificationChannel.DISCORD])))

        assert slack_result["success"] is True
        assert discord_result["success"] is True
        assert [post["kwargs"]["allow_redirects"] for post in captured_posts] == [False, False]

    def test_redirect_response_is_not_followed(self, monkeypatch):
        self._allow_example_dns(monkeypatch)
        captured_posts = []
        self._install_fake_client_session(monkeypatch, captured_posts, status=302)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is False
        assert "HTTP 302" in result["error"]
        assert captured_posts[0]["kwargs"]["allow_redirects"] is False

    def test_smtp_starttls_uses_verified_context(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, _message):
                captured["sent"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["recipient@example.com"],
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message([NotificationChannel.EMAIL])))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED

    def test_smtp_refuses_plaintext_auth(self, monkeypatch):
        captured = {"login_called": False}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, **_kwargs):
                raise AssertionError("STARTTLS should not be called when disabled")

            def login(self, *_args):
                captured["login_called"] = True

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["recipient@example.com"],
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message([NotificationChannel.EMAIL])))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert captured["login_called"] is False
