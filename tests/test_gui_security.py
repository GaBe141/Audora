"""Security tests for GUI command construction and CSV export caps."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    MAX_CSV_EXPORT_ROWS,
    _cap_export_rows,
    _validate_command_args,
    _validate_demo_mode,
)


class TestGuiCommandSafety:
    """GUI must not pass untrusted strings into subprocess argv."""

    def test_demo_allowlist_accepts_known_modes(self):
        assert _validate_demo_mode("statistical") == "statistical"
        assert "all" in ALLOWED_DEMO_MODES

    def test_demo_allowlist_rejects_unknown_modes(self):
        with pytest.raises(ValueError, match="demo mode"):
            _validate_demo_mode("; rm -rf /")
        with pytest.raises(ValueError, match="demo mode"):
            _validate_demo_mode("statistical && id")

    def test_command_args_reject_nul_and_non_strings(self):
        with pytest.raises(ValueError, match="NUL-free"):
            _validate_command_args(["python", "main.py\x00--demo"])
        with pytest.raises(ValueError, match="NUL-free"):
            _validate_command_args(["python", 1])  # type: ignore[list-item]


class TestGuiCsvExportCap:
    """History CSV export must not dump unbounded attacker-controlled tables."""

    def test_caps_oversized_export_payloads(self):
        rows = [{"n": i} for i in range(MAX_CSV_EXPORT_ROWS + 50)]
        capped = _cap_export_rows(rows)
        assert len(capped) == MAX_CSV_EXPORT_ROWS
