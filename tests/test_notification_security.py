"""Security tests for notification rendering and transport hardening."""

import ssl
from unittest.mock import MagicMock, patch

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

    def test_private_webhook_override_requires_local_environment(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        monkeypatch.delenv("AUDORA_ENV", raising=False)
        assert svc._allow_private_webhooks() is False

        monkeypatch.setenv("AUDORA_ENV", "development")
        assert svc._allow_private_webhooks() is True


class TestTemplateRendering:
    """Validate template rendering uses an allowlisted sandbox."""

    def test_rejects_unknown_template_names(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Unknown notification template"):
            svc._render_template({"template": "attacker_controlled"})

    def test_renders_known_template_without_exposing_template_key(self):
        svc = EnhancedNotificationService()
        rendered = svc._render_template(
            {
                "template": "breakthrough_alert",
                "track_name": "Song",
                "artist": "Artist",
                "current_score": 91,
                "growth_rate": 2,
                "platform_count": 3,
                "days_to_viral": 4,
            }
        )

        assert "Song by Artist" in rendered
        assert "breakthrough_alert" not in rendered


class TestNotificationTransportHardening:
    """Validate outbound notification channels use safer transports."""

    @pytest.mark.asyncio
    async def test_email_rejects_plaintext_credentials(self):
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
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is False
        assert "without TLS" in result["error"]

    @pytest.mark.asyncio
    async def test_email_starttls_uses_verified_ssl_context(self):
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
        server = MagicMock()
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = await svc._send_email(message)

        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    @pytest.mark.asyncio
    async def test_webhook_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        captured_kwargs = {}

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, *, allow_private=False: url,
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = await svc._send_webhook(message)

        assert result["success"] is True
        assert captured_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_slack_and_discord_disable_redirect_following(self, monkeypatch):
        captured_kwargs = []

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.append(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        slack = EnhancedNotificationService()
        slack.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(slack, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        slack_result = await slack._send_slack(message)

        discord = EnhancedNotificationService()
        discord.config["discord"]["webhook_url"] = "https://example.com/discord"
        monkeypatch.setattr(discord, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        discord_result = await discord._send_discord(message)

        assert slack_result["success"] is True
        assert discord_result["success"] is True
        assert [kwargs["allow_redirects"] for kwargs in captured_kwargs] == [False, False]
