"""Security-focused tests for report path handling in core.main_app."""

import json
from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp


def _build_minimal_app() -> ComprehensiveMusicDiscoveryApp:
    """Create app instance without running heavy constructor side effects."""
    return ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)


def test_save_discovery_report_default_path_stays_in_data_dir():
    app = _build_minimal_app()
    payload = {"ok": True}

    output = app.save_discovery_report(payload)
    output_path = Path(output).resolve()

    assert "data" in output_path.parts
    assert output_path.name.startswith("comprehensive_discovery_report_")
    assert output_path.suffix == ".json"

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved == payload

    output_path.unlink(missing_ok=True)


def test_save_discovery_report_rejects_absolute_path():
    app = _build_minimal_app()
    with pytest.raises(ValueError, match="Absolute report paths are not allowed"):
        app.save_discovery_report({"ok": True}, custom_filename="/tmp/escape.json")


def test_save_discovery_report_rejects_path_traversal():
    app = _build_minimal_app()
    with pytest.raises(ValueError, match="must remain within the data directory"):
        app.save_discovery_report({"ok": True}, custom_filename="../../../tmp/escape.json")
