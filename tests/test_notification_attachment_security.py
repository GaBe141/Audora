"""Security tests for notification email attachment validation."""

from pathlib import Path

import pytest

from core.notification_service import EnhancedNotificationService


class TestAttachmentPathValidation:
    """Validate attachment path hardening against traversal/exfiltration."""

    def test_rejects_attachment_outside_allowed_roots(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOTS", str(allowed))

        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="outside allowed roots"):
            svc._validate_attachment_path(str(outside))

    def test_accepts_attachment_inside_allowed_roots(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        allowed_file = allowed / "ok.txt"
        allowed_file.write_text("ok", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOTS", str(allowed))

        svc = EnhancedNotificationService()
        assert svc._validate_attachment_path(str(allowed_file)) == allowed_file.resolve()

    def test_rejects_symlink_attachment(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        target = allowed / "target.txt"
        target.write_text("target", encoding="utf-8")
        link = allowed / "link.txt"
        link.symlink_to(target)
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOTS", str(allowed))

        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Symlink"):
            svc._validate_attachment_path(str(link))

    def test_rejects_oversized_attachment(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        big_file = allowed / "big.bin"
        big_file.write_bytes(b"0" * 11)
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOTS", str(allowed))
        monkeypatch.setenv("AUDORA_MAX_ATTACHMENT_BYTES", "10")

        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="maximum allowed size"):
            svc._validate_attachment_path(str(big_file))
