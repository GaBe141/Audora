"""Security tests for SMTP TLS behavior in notification email delivery."""

from unittest.mock import patch

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class _FakeSMTP:
    """Minimal SMTP test double for capturing starttls usage."""

    last_instance = None

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.starttls_context = None
        self.logged_in = False
        self.sent_messages = []
        _FakeSMTP.last_instance = self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self, context=None):
        self.starttls_context = context
        return 220, b"ok"

    def login(self, _username, _password):
        self.logged_in = True

    def send_message(self, message):
        self.sent_messages.append(message)


def _build_message() -> NotificationMessage:
    return NotificationMessage(
        title="security test",
        content="verify smtp tls configuration",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )


def test_email_uses_verified_tls_context():
    service = EnhancedNotificationService()
    service.config["email"] = {
        "smtp_server": "smtp.example.com",
        "port": 587,
        "username": "user",
        "password": "pass",
        "from_address": "from@example.com",
        "recipients": ["to@example.com"],
        "use_tls": True,
        "timeout_seconds": 10,
    }

    fake_context = object()
    with (
        patch("core.notification_service.smtplib.SMTP", new=_FakeSMTP),
        patch("core.notification_service.ssl.create_default_context", return_value=fake_context),
    ):
        result = __import__("asyncio").run(service._send_email(_build_message()))

    smtp = _FakeSMTP.last_instance
    assert result["success"] is True
    assert smtp is not None
    assert smtp.starttls_context is fake_context
    assert smtp.logged_in is True
    assert len(smtp.sent_messages) == 1
