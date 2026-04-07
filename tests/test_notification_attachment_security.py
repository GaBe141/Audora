"""Tests for secure notification attachment handling."""

from core.notification_service import ATTACHMENT_BASE_DIR, EnhancedNotificationService


def test_resolve_safe_attachment_path_allows_files_in_data(tmp_path):
    svc = EnhancedNotificationService()
    safe_file = ATTACHMENT_BASE_DIR / "reports" / "attachment.txt"
    safe_file.parent.mkdir(parents=True, exist_ok=True)
    safe_file.write_text("ok", encoding="utf-8")

    resolved = svc._resolve_safe_attachment_path(str(safe_file))
    assert resolved == safe_file.resolve()


def test_resolve_safe_attachment_path_rejects_files_outside_data(tmp_path):
    svc = EnhancedNotificationService()
    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("sensitive", encoding="utf-8")

    resolved = svc._resolve_safe_attachment_path(str(outside_file))
    assert resolved is None


def test_resolve_safe_attachment_path_rejects_nonexistent_path():
    svc = EnhancedNotificationService()
    missing = ATTACHMENT_BASE_DIR / "reports" / "does-not-exist.txt"
    resolved = svc._resolve_safe_attachment_path(str(missing))
    assert resolved is None
