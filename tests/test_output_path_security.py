"""Security tests for constrained output path helpers."""

import pytest

from core.utils import resolve_output_path


def test_resolve_output_path_rejects_parent_traversal(tmp_path):
    with pytest.raises(ValueError, match="within"):
        resolve_output_path("../outside.json", base_dir=tmp_path)


def test_resolve_output_path_rejects_absolute_path_outside_base(tmp_path):
    with pytest.raises(ValueError, match="within"):
        resolve_output_path("/tmp/outside.json", base_dir=tmp_path)


def test_resolve_output_path_rejects_unexpected_suffix(tmp_path):
    with pytest.raises(ValueError, match="suffixes"):
        resolve_output_path("report.txt", base_dir=tmp_path, allowed_suffixes={".json"})


def test_resolve_output_path_accepts_path_inside_base(tmp_path):
    path = resolve_output_path(
        "reports/report.json",
        base_dir=tmp_path,
        allowed_suffixes={".json"},
    )
    assert path == tmp_path / "reports/report.json"
