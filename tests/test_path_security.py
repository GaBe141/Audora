"""Security tests for filesystem path validation helpers."""

from pathlib import Path

import pytest

from core.utils import resolve_path_within_base, write_json


def test_resolve_path_within_base_rejects_absolute_outside_path(tmp_path):
    base = tmp_path / "safe"
    outside = (tmp_path / "escape.json").resolve()
    with pytest.raises(ValueError, match="outside allowed directory"):
        resolve_path_within_base(outside, base)


def test_resolve_path_within_base_keeps_relative_path_inside(tmp_path):
    base = tmp_path / "safe"
    resolved = resolve_path_within_base("nested/report.json", base)
    assert resolved == (base / "nested/report.json").resolve()


def test_write_json_rejects_escape_from_base_dir(tmp_path):
    base_dir = tmp_path / "safe"
    with pytest.raises(ValueError, match="outside allowed directory"):
        write_json(tmp_path / "escape.json", {"ok": True}, base_dir=base_dir)

    output = write_json(base_dir / "nested" / "ok.json", {"ok": True}, base_dir=base_dir)
    assert Path(output).resolve() == (base_dir / "nested" / "ok.json").resolve()
