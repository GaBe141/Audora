"""Security tests for filesystem path validation helpers."""

from pathlib import Path

import pytest

from core.data_store import EnhancedMusicDataStore
from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import write_json


def test_main_app_rejects_absolute_custom_path_outside_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    outside_path = (tmp_path / "outside.json").resolve()
    with pytest.raises(ValueError, match="data/reports"):
        app.save_discovery_report({"ok": True}, custom_filename=str(outside_path))


def test_data_store_export_rejects_path_outside_exports(tmp_path):
    db_path = tmp_path / "audora.db"
    store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
    try:
        with pytest.raises(ValueError, match="data/exports"):
            store.export_to_csv("trends", str((tmp_path / "escape.csv").resolve()))
    finally:
        store.close_pool()


def test_data_store_export_writes_inside_exports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / "audora.db"
    store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
    try:
        output = store.export_to_csv("trends", "safe/export.csv")
        assert Path(output).resolve() == (tmp_path / "data/exports/safe/export.csv").resolve()
    finally:
        store.close_pool()


def test_write_json_rejects_escape_from_base_dir(tmp_path):
    base_dir = tmp_path / "safe"
    with pytest.raises(ValueError, match="base_dir"):
        write_json(tmp_path / "escape.json", {"ok": True}, base_dir=base_dir)

    output = write_json(base_dir / "nested" / "ok.json", {"ok": True}, base_dir=base_dir)
    assert Path(output).resolve() == (base_dir / "nested" / "ok.json").resolve()


def test_notification_save_config_rejects_path_outside_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    # Build notification service without invoking app initialization side effects.
    from core.notification_service import EnhancedNotificationService

    notifier = EnhancedNotificationService()
    with pytest.raises(ValueError):
        notifier.save_config(str((tmp_path / "outside" / "notif.json").resolve()))
