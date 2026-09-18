"""Security tests for notification webhook URL validation."""

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


class TestNotificationTransportHardening:
    """SMTP TLS and webhook redirect controls."""

    def _email_config(self, **overrides):
        config = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        config.update(overrides)
        return config

    def test_rejects_plaintext_smtp_authentication(self):
        import asyncio

        from core.notification_service import (
            NotificationMessage,
            NotificationPriority,
        )

        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config(use_tls=False)
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        import asyncio
        import ssl
        from unittest.mock import MagicMock

        import core.notification_service as notification_module
        from core.notification_service import (
            NotificationMessage,
            NotificationPriority,
        )

        smtp_instance = MagicMock()
        monkeypatch.setattr(notification_module.smtplib, "SMTP", MagicMock(return_value=smtp_instance))

        captured = {}
        real_create_default_context = ssl.create_default_context

        def fake_create_default_context():
            ctx = real_create_default_context()
            captured["context"] = ctx
            return ctx

        monkeypatch.setattr(notification_module.ssl, "create_default_context", fake_create_default_context)

        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        message = NotificationMessage(
            title="Alert\nBcc: attacker@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        smtp_instance.starttls.assert_called_once()
        kwargs = smtp_instance.starttls.call_args.kwargs
        assert "context" in kwargs
        assert kwargs["context"] is captured["context"]
        assert kwargs["context"].check_hostname is True
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        sent_message = smtp_instance.send_message.call_args.args[0]
        assert "\n" not in sent_message["Subject"]
        assert "\r" not in sent_message["Subject"]
        assert sent_message["Subject"] == "AlertBcc: attacker@example.com"
        html_part = sent_message.get_payload()[1].get_payload(decode=True).decode("utf-8")
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_webhook_posts_disable_redirects(self, monkeypatch):
        import asyncio

        import core.notification_service as notification_module
        from core.notification_service import (
            NotificationMessage,
            NotificationPriority,
        )

        captured = {}

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return DummyResponse()

        monkeypatch.setattr(notification_module.aiohttp, "ClientSession", DummySession)
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False

    def test_slack_and_discord_posts_disable_redirects(self, monkeypatch):
        import asyncio

        import core.notification_service as notification_module
        from core.notification_service import (
            NotificationMessage,
            NotificationPriority,
        )

        captured = []

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured.append(kwargs)
                return DummyResponse()

        monkeypatch.setattr(notification_module.aiohttp, "ClientSession", DummySession)
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        slack_result = asyncio.run(svc._send_slack(message))
        discord_result = asyncio.run(svc._send_discord(message))
        assert slack_result["success"] is True
        assert discord_result["success"] is True
        assert captured[0].get("allow_redirects") is False
        assert captured[1].get("allow_redirects") is False
