"""Security tests for report-path constraints used by main_app."""

from pathlib import Path

import pytest

from core.utils import resolve_path_within_base


def test_report_path_rejects_parent_traversal(tmp_path):
    """Reject traversals that escape the reports directory."""
    reports_dir = (tmp_path / "data" / "reports").resolve()
    with pytest.raises(ValueError):
        resolve_path_within_base("../escape.json", reports_dir)


def test_report_path_allows_nested_relative_path(tmp_path):
    """Allow safe relative paths resolved under reports directory."""
    reports_dir = (tmp_path / "data" / "reports").resolve()
    output_path = resolve_path_within_base("safe/report.json", reports_dir)
    assert output_path == reports_dir / "safe" / "report.json"
    assert reports_dir in output_path.parents
