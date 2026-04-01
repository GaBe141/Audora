"""Security tests for safe report file path handling."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import save_report


def test_save_report_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="Unsafe report filename"):
        save_report({"ok": True}, filename="../escape.json", output_dir=str(tmp_path))


def test_save_report_allows_file_within_output_dir(tmp_path):
    saved = save_report({"ok": True}, filename="safe.json", output_dir=str(tmp_path))
    assert saved == (tmp_path / "safe.json").resolve()
    assert saved.exists()


def test_save_discovery_report_rejects_outside_base_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = object.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="Unsafe report filename"):
        app.save_discovery_report({"ok": True}, "../outside.json")


def test_save_discovery_report_allows_nested_file_under_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = object.__new__(ComprehensiveMusicDiscoveryApp)
    saved_path = app.save_discovery_report({"ok": True}, "reports/safe.json")
    expected = (Path(tmp_path) / "data" / "reports" / "safe.json").resolve()
    assert Path(saved_path).resolve() == expected
    assert expected.exists()
