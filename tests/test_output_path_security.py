"""Security tests for safe output path handling and report writers."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import build_safe_output_path


def test_build_safe_output_path_rejects_absolute_paths() -> None:
    with pytest.raises(ValueError, match="Absolute output paths"):
        build_safe_output_path(
            "/tmp/evil.json",
            base_dir=Path("data"),
            default_filename="report.json",
        )


def test_build_safe_output_path_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="escapes the allowed base directory"):
        build_safe_output_path(
            "../outside.json",
            base_dir=Path("data"),
            default_filename="report.json",
        )


def test_save_discovery_report_writes_under_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    out = app.save_discovery_report({"ok": True}, "subdir/report.json")

    output_path = Path(out).resolve()
    data_dir = (tmp_path / "data").resolve()
    output_path.relative_to(data_dir)
    assert output_path.is_file()

