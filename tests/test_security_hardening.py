"""Regression tests for security hardening changes."""

from core.notification_service import EnhancedNotificationService


def test_email_header_sanitization_removes_crlf_and_nul():
    svc = EnhancedNotificationService()
    raw = "Alert\r\nBcc: attacker@example.com\0"
    cleaned = svc._sanitize_email_header(raw)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\0" not in cleaned
    assert "Bcc:" in cleaned


def test_email_header_sanitization_fallback_for_empty():
    svc = EnhancedNotificationService()
    assert svc._sanitize_email_header("\r\n\0 ") == "Audora Notification"


def test_gui_blocks_remote_admin_actions_by_default():
    from gui.app import _admin_access_block_message, _can_run_admin_action, app

    with app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "10.10.10.10"}):
        assert _can_run_admin_action() is False
        assert "Blocked" in _admin_access_block_message()
