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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_redirect_status_codes(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="redirect"):
            svc._reject_redirect_status(302)

    def test_attachment_path_must_stay_in_allowlisted_dirs(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed = tmp_path / "exports"
        allowed.mkdir()
        safe_file = allowed / "report.csv"
        safe_file.write_text("ok")
        outside = tmp_path / "secret.txt"
        outside.write_text("nope")
        monkeypatch.setattr(svc, "_attachment_roots", lambda: [allowed.resolve()])
        assert svc._resolve_attachment_path(str(safe_file)) == safe_file.resolve()
        assert svc._resolve_attachment_path(str(outside)) is None

    def test_html_email_escapes_content(self, monkeypatch):
        import asyncio
        import ssl

        from core.notification_service import NotificationMessage, NotificationPriority

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        captured = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, *args):
                captured["login"] = args

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        message = NotificationMessage(
            title="Alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        html_body = captured["msg"].get_payload()[1].get_payload()
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True

    def test_refuses_smtp_auth_without_tls(self):
        import asyncio

        from core.notification_service import NotificationMessage, NotificationPriority

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Alert",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_webhook_posts_disable_redirects(self, monkeypatch):
        import asyncio

        from core.notification_service import NotificationMessage, NotificationPriority

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured = {}

        class FakeResponse:
            status = 200

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
                captured["kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        message = NotificationMessage(
            title="Alert",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_webhook_rejects_redirect_response(self, monkeypatch):
        import asyncio

        from core.notification_service import NotificationMessage, NotificationPriority

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

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
                return FakeResponse()

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        message = NotificationMessage(
            title="Alert",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()
