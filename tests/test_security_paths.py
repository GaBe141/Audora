"""Security tests for path traversal and file exfiltration protections."""

from pathlib import Path

import pytest

from core.notification_service import EnhancedNotificationService
from core.data_store import EnhancedMusicDataStore
from core.utils import save_dataframe, save_report, write_json


class TestSecureWritePaths:
    """Validate write helpers reject path traversal."""

    def test_write_json_rejects_path_outside_repo(self):
        with pytest.raises(ValueError, match="outside allowed base directory"):
            write_json("../outside.json", {"ok": True})

    def test_save_dataframe_rejects_path_outside_repo(self):
        class DummyDf:
            def to_csv(self, *_args, **_kwargs):
                return None

        with pytest.raises(ValueError, match="outside allowed base directory"):
            save_dataframe(DummyDf(), "../outside.csv")

    def test_save_report_rejects_filename_with_path_components(self):
        with pytest.raises(ValueError, match="simple file name"):
            save_report({"x": 1}, filename="../escape.json")

    def test_write_json_allows_path_within_explicit_allowed_base(self, tmp_path):
        target = tmp_path / "nested" / "out.json"
        saved = write_json(target, {"ok": True}, allowed_base_dir=tmp_path)
        assert saved.exists()


class TestAttachmentPathSecurity:
    """Validate attachment path restrictions for notifications."""

    def test_attachment_path_rejects_parent_escape(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="outside allowed directories"):
            svc._resolve_allowed_attachment_path("../../etc/passwd")

    def test_attachment_path_allows_file_in_project_data_dir(self):
        svc = EnhancedNotificationService()
        allowed = svc.project_root / "data" / "attachment-test.txt"
        allowed.parent.mkdir(parents=True, exist_ok=True)
        allowed.write_text("safe", encoding="utf-8")
        resolved = svc._resolve_allowed_attachment_path(str(allowed))
        assert resolved == allowed.resolve()


class TestDataExportPathSecurity:
    """Validate export path restrictions in data_store."""

    def test_export_to_csv_rejects_path_outside_repo(self, temp_db_path):
        store = EnhancedMusicDataStore(db_path=str(temp_db_path))
        with pytest.raises(ValueError, match="outside allowed base directory"):
            store.export_to_csv("trends", "../outside.csv")

