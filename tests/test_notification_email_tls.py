"""Security tests for SMTP TLS behavior in notifications."""

import asyncio
from unittest.mock import MagicMock, patch

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestNotificationEmailTls:
    """Ensure SMTP connections use secure TLS defaults."""

    def _build_message(self) -> NotificationMessage:
        return NotificationMessage(
            title="TLS test",
            content="Testing secure SMTP transport",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    def test_email_uses_verified_tls_context_by_default(
        self, smtp_cls: MagicMock, create_default_context: MagicMock
    ) -> None:
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["user@example.com"]
        svc.config["email"]["use_tls"] = True
        svc.config["email"]["verify_tls"] = True

        smtp_instance = smtp_cls.return_value
        mock_context = MagicMock()
        create_default_context.return_value = mock_context

        result = asyncio.run(svc._send_email(self._build_message()))

        assert result["success"] is True
        create_default_context.assert_called_once_with()
        smtp_instance.starttls.assert_called_once_with(context=mock_context)

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    def test_email_allows_explicit_unverified_tls_opt_out(
        self, smtp_cls: MagicMock, create_default_context: MagicMock
    ) -> None:
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["user@example.com"]
        svc.config["email"]["use_tls"] = True
        svc.config["email"]["verify_tls"] = False

        smtp_instance = smtp_cls.return_value

        result = asyncio.run(svc._send_email(self._build_message()))

        assert result["success"] is True
        create_default_context.assert_not_called()
        smtp_instance.starttls.assert_called_once_with()
