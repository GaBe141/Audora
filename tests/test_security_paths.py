"""Security regression tests for path traversal protections."""

from datetime import datetime
from pathlib import Path
import sys

import pytest

from core.data_store import EnhancedMusicDataStore
from core.utils import resolve_path_within_base, write_json
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_resolve_path_within_base_rejects_traversal(tmp_path):
    base = tmp_path / "safe"
    base.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="escapes base directory"):
        resolve_path_within_base("../outside.json", base)


def test_write_json_rejects_traversal_when_base_is_set(tmp_path):
    base = tmp_path / "reports"
    base.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="escapes base directory"):
        write_json("../secret.json", {"ok": True}, safe_base_dir=base)


def test_social_discovery_report_stays_in_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine(config={})
    report = {"timestamp": datetime.now().isoformat(), "ok": True}

    with pytest.raises(ValueError, match="escapes base directory"):
        engine.save_discovery_report(report, filepath="../outside.json")

    saved = Path(engine.save_discovery_report(report, filepath="valid_report.json")).resolve()
    data_dir = (tmp_path / "data").resolve()
    assert saved.is_file()
    assert saved.is_relative_to(data_dir)


def test_main_app_report_stays_in_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    integrations_dir = Path(__file__).resolve().parent.parent / "integrations"
    if str(integrations_dir) not in sys.path:
        sys.path.insert(0, str(integrations_dir))

    from core.main_app import ComprehensiveMusicDiscoveryApp

    app = object.__new__(ComprehensiveMusicDiscoveryApp)
    report = {"timestamp": datetime.now().isoformat(), "ok": True}

    with pytest.raises(ValueError, match="escapes base directory"):
        app.save_discovery_report(report, custom_filename="../outside.json")

    saved = Path(app.save_discovery_report(report, custom_filename="nested/report.json")).resolve()
    data_dir = (tmp_path / "data").resolve()
    assert saved.is_file()
    assert saved.is_relative_to(data_dir)


def test_data_store_export_rejects_path_traversal(data_store):
    with pytest.raises(ValueError, match="escapes base directory"):
        data_store.export_to_csv("trends", "../outside.csv")


def test_export_to_csv_rejects_paths_outside_export_base(tmp_path):
    db_path = tmp_path / "store.db"
    backup_dir = tmp_path / "backups"
    store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(backup_dir))
    try:
        with pytest.raises(ValueError, match="escapes base directory"):
            store.export_to_csv("trends", "../escape.csv")
    finally:
        store.close_pool()
