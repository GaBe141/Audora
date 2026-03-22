"""Security tests for report path handling in main_app."""

from pathlib import Path

import pytest

from core.main_app import _resolve_safe_report_path


class TestResolveSafeReportPath:
    """Validate path traversal protections for discovery report writes."""

    def test_generates_default_path_in_base_dir(self, tmp_path):
        resolved = _resolve_safe_report_path(None, base_dir=tmp_path)
        assert resolved.is_relative_to(tmp_path.resolve())
        assert resolved.name.startswith("comprehensive_discovery_report_")
        assert resolved.suffix == ".json"

    def test_allows_nested_relative_path_within_base_dir(self, tmp_path):
        resolved = _resolve_safe_report_path("nested/report.json", base_dir=tmp_path)
        assert resolved == (tmp_path / "nested" / "report.json").resolve()

    def test_rejects_parent_directory_traversal(self, tmp_path):
        with pytest.raises(ValueError, match="must stay within the data directory"):
            _resolve_safe_report_path("../escape.json", base_dir=tmp_path)

    def test_rejects_absolute_paths(self, tmp_path):
        absolute_path = Path("/tmp/escape.json")
        with pytest.raises(ValueError, match="Absolute report paths are not allowed"):
            _resolve_safe_report_path(str(absolute_path), base_dir=tmp_path)
