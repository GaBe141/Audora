"""Security tests for filesystem path traversal protections."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.data_store import EnhancedMusicDataStore
from core.utils import resolve_path_within_base, write_json
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_resolve_path_within_base_allows_file_under_base(tmp_path):
    base_dir = tmp_path / "data"
    base_dir.mkdir(parents=True, exist_ok=True)

    resolved = resolve_path_within_base("reports/output.json", base_dir)

    assert resolved == (base_dir / "reports" / "output.json").resolve()


def test_resolve_path_within_base_blocks_traversal(tmp_path):
    base_dir = tmp_path / "data"
    base_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="Refusing to write outside"):
        resolve_path_within_base("../escape.json", base_dir)


def test_write_json_blocks_outside_allowed_base(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="Refusing to write outside"):
        write_json("../not_allowed.json", {"ok": True}, allowed_base_dir=allowed)


def test_main_app_save_discovery_report_rejects_traversal(monkeypatch):
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    app.report_base_dir = Path("data").resolve()

    with pytest.raises(ValueError, match="Refusing to write outside"):
        app.save_discovery_report({"status": "ok"}, custom_filename="../bad.json")


def test_social_engine_save_discovery_report_rejects_traversal():
    engine = SocialMusicDiscoveryEngine({})

    with pytest.raises(ValueError, match="Refusing to write outside"):
        engine.save_discovery_report({"status": "ok"}, filepath="../bad.json")


def test_export_to_csv_rejects_traversal(data_store):
    with pytest.raises(ValueError, match="Refusing to write outside"):
        data_store.export_to_csv("trends", "../escape.csv")


def test_export_to_csv_allows_data_relative_path(data_store):
    output = data_store.export_to_csv("trends", "reports/trends.csv")
    output_path = Path(output).resolve()
    expected_base = data_store.export_base_dir.resolve()

    assert expected_base in output_path.parents
    assert output_path.name == "trends.csv"
