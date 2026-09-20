"""Security tests for GUI command and export helpers."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    MAX_CSV_EXPORT_ROWS,
    cap_csv_rows,
    validate_command_args,
    validate_demo_mode,
)


class TestDemoModeAllowlist:
    def test_accepts_known_modes(self):
        for mode in ALLOWED_DEMO_MODES:
            assert validate_demo_mode(mode) == mode

    def test_rejects_unknown_and_non_string_modes(self):
        with pytest.raises(ValueError, match="Invalid demo mode"):
            validate_demo_mode("rm -rf /")
        with pytest.raises(ValueError, match="Invalid demo mode"):
            validate_demo_mode(["statistical"])


class TestCommandArgs:
    def test_accepts_string_args(self):
        args = ["python", "main.py", "--demo", "statistical"]
        assert validate_command_args(args) == args

    def test_rejects_nul_and_non_strings(self):
        with pytest.raises(ValueError, match="Invalid command arguments"):
            validate_command_args(["python", "main.py\x00--demo"])
        with pytest.raises(ValueError, match="Invalid command arguments"):
            validate_command_args(["python", 123])  # type: ignore[list-item]


class TestCsvExportCap:
    def test_caps_oversized_exports(self):
        rows = [{"n": i} for i in range(MAX_CSV_EXPORT_ROWS + 25)]
        assert len(cap_csv_rows(rows)) == MAX_CSV_EXPORT_ROWS

    def test_leaves_small_exports_unchanged(self):
        rows = [{"n": 1}, {"n": 2}]
        assert cap_csv_rows(rows) == rows
