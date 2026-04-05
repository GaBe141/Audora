"""Security tests for hardening in core.main_app source."""

from pathlib import Path


def test_main_app_enforces_report_path_boundary_and_extension():
    """Ensure traversal checks and file-type guard remain in place."""
    source = (Path(__file__).resolve().parents[1] / "core" / "main_app.py").read_text(
        encoding="utf-8"
    )

    assert "filepath.relative_to(base_dir)" in source
    assert "custom_filename escapes the allowed data directory" in source
    assert "filepath.suffix.lower() != \".json\"" in source
    assert "Discovery reports must be saved with a .json extension" in source

