"""Regression tests for critical security hardening changes."""

import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def test_message_key_is_stable_and_content_based():
    """Deduplication keys should be deterministic across process restarts."""
    svc = EnhancedNotificationService()
    message = NotificationMessage(
        title="Test",
        content="Hello world",
        priority=NotificationPriority.MEDIUM,
        channels=[NotificationChannel.CONSOLE, NotificationChannel.EMAIL],
        data={"x": 1},
    )

    key = svc._generate_message_key(message)

    expected_fingerprint = {
        "title": "Test",
        "content": "Hello world",
        "priority": "medium",
        "channels": ["console", "email"],
        "data": {"x": 1},
    }
    expected_digest = hashlib.sha256(
        json.dumps(
            expected_fingerprint, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
    ).hexdigest()
    assert key == f"{expected_digest}:medium"


def test_validate_attachment_blocks_path_outside_allowed_dirs(
    tmp_path, monkeypatch
):
    """Attachment validation must reject files outside allowlisted directories."""
    safe_dir = tmp_path / "exports"
    safe_dir.mkdir()
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("top-secret", encoding="utf-8")

    monkeypatch.setenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", str(safe_dir))
    svc = EnhancedNotificationService()

    try:
        svc._validate_attachment_path(str(secret_file))
        assert False, "Expected ValueError for disallowed attachment directory"
    except ValueError as e:
        assert "outside allowed directories" in str(e)


def test_send_email_enforces_starttls_support(monkeypatch):
    """Email sending should fail if TLS is requested but STARTTLS unavailable."""
    monkeypatch.setenv("SMTP_SERVER", "smtp.example.com")
    monkeypatch.setenv("EMAIL_RECIPIENTS", "a@example.com")

    svc = EnhancedNotificationService()
    message = NotificationMessage(
        title="Test",
        content="Body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )

    smtp_mock = Mock()
    smtp_mock.__enter__ = Mock(return_value=smtp_mock)
    smtp_mock.__exit__ = Mock(return_value=False)
    smtp_mock.has_extn.return_value = False

    with patch("core.notification_service.smtplib.SMTP", return_value=smtp_mock):
        result = __import__("asyncio").run(svc._send_email(message))
        assert result["success"] is False
        assert "STARTTLS" in result["error"]


def test_run_command_uses_safe_argument_list():
    """Lint-fix helper should invoke subprocess without shell=True."""
    from scripts.fix_linting_issues import run_command

    with patch("scripts.fix_linting_issues.subprocess.run") as run_mock:
        run_mock.return_value = Mock()
        run_mock.return_value.returncode = 0
        run_mock.return_value.stderr = ""
        ok = run_command(["echo", "hello"], "test")
        assert ok is True
        _, kwargs = run_mock.call_args
        assert kwargs.get("shell") is not True
