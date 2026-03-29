"""Transport hardening tests for notification delivery channels."""

from unittest.mock import MagicMock, patch

from core.notification_service import EnhancedNotificationService


class TestNotificationTransportSecurity:
    """Verify secure defaults for outbound notification transports."""

    def test_email_starttls_uses_verified_context(self):
        svc = EnhancedNotificationService()
        msg = MagicMock()
        msg.title = "Test"
        msg.content = "Body"
        msg.priority = MagicMock()
        msg.template_vars = None
        msg.attachments = None

        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }

        with patch("core.notification_service.smtplib.SMTP") as smtp_cls, patch(
            "core.notification_service.ssl.create_default_context"
        ) as create_ctx:
            smtp_instance = smtp_cls.return_value
            ctx_obj = object()
            create_ctx.return_value = ctx_obj

            # Run coroutine synchronously for this test
            import asyncio

            asyncio.run(svc._send_email(msg))

            smtp_instance.starttls.assert_called_once_with(context=ctx_obj)

