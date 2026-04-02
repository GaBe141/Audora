"""Security tests for email notification handling."""

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestEmailSecurity:
    """Validate SMTP hardening behavior."""

    def test_sanitize_header_value_removes_crlf(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header_value("Bad\r\nHeader") == "Bad  Header"

    def test_send_email_strips_empty_recipients(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["", "   "]
        message = NotificationMessage(
            title="Security Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = __import__("asyncio").run(svc._send_email(message))
        assert result["success"] is False
        assert "Email not configured" in result["error"]
