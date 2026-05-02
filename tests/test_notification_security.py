"""Security tests for notification delivery hardening."""

import asyncio

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

    def test_rejects_webhook_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    async def _build_webhook_connector(self, svc: EnhancedNotificationService, url: str):
        return svc._webhook_connector(url)

    def test_webhook_connector_pins_validated_dns_results(self, mocker):
        svc = EnhancedNotificationService()
        mocker.patch(
            "core.notification_service.socket.getaddrinfo",
            return_value=[
                (
                    2,
                    1,
                    6,
                    "",
                    ("93.184.216.34", 443),
                )
            ],
        )

        validated_url, connector = asyncio.run(
            self._build_webhook_connector(svc, "https://example.com/webhook")
        )

        assert validated_url == "https://example.com/webhook"
        assert connector._resolver.resolved_hosts == {"example.com": [("93.184.216.34", 2)]}


class TestNotificationDeliverySecurity:
    """Validate secure delivery behavior around email and webhook sending."""

    class _Response:
        status = 302

        async def text(self):
            return "redirect"

    class _ResponseContext:
        async def __aenter__(self):
            return TestNotificationDeliverySecurity._Response()

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    class _ClientSessionContext:
        def __init__(self):
            self.post_call_kwargs = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        def post(self, *args, **kwargs):
            self.post_call_kwargs = kwargs
            return TestNotificationDeliverySecurity._ResponseContext()

    def test_webhook_sender_disables_redirects(self, mocker):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        connector = mocker.Mock()
        mocker.patch.object(
            svc,
            "_webhook_connector",
            return_value=("https://example.com/webhook", connector),
        )
        session = self._ClientSessionContext()
        mocker.patch("core.notification_service.aiohttp.ClientSession", return_value=session)

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="redirect test",
                    content="content",
                    priority=NotificationPriority.HIGH,
                    channels=[NotificationChannel.WEBHOOK],
                )
            )
        )

        assert result["success"] is False
        assert session.post_call_kwargs["allow_redirects"] is False

    def test_email_html_body_escapes_notification_content(self, mocker):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        smtp = mocker.patch("core.notification_service.smtplib.SMTP").return_value

        message = NotificationMessage(
            title="escape test",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        sent_message = smtp.send_message.call_args.args[0]
        html_part = sent_message.get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_email_tls_uses_verified_default_context(self, mocker):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )
        smtp = mocker.patch("core.notification_service.smtplib.SMTP").return_value
        ssl_context = mocker.patch(
            "core.notification_service.ssl.create_default_context",
            return_value=mocker.sentinel.ssl_context,
        )

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="tls test",
                    content="content",
                    priority=NotificationPriority.MEDIUM,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        ssl_context.assert_called_once_with()
        smtp.starttls.assert_called_once_with(context=mocker.sentinel.ssl_context)

    def test_rejects_email_attachments_outside_configured_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["attachment_base_dir"] = str(tmp_path / "allowed")
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="outside the allowed attachment directory"):
            svc._resolve_attachment_path(str(outside_file))

    def test_allows_email_attachments_inside_configured_directory(self, tmp_path):
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        attachment = allowed_dir / "report.txt"
        attachment.write_text("safe report", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["attachment_base_dir"] = str(allowed_dir)

        assert svc._resolve_attachment_path("report.txt") == attachment.resolve()
