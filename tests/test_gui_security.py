"""Security tests for GUI command and CSV export handling."""

from gui.app import (
    _ALLOWED_DEMO_VALUES,
    _MAX_CSV_EXPORT_ROWS,
    _sanitize_csv_value,
)


def test_demo_allowlist_matches_cli_choices():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == _ALLOWED_DEMO_VALUES


def test_csv_formula_injection_is_neutralized():
    assert _sanitize_csv_value("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert _sanitize_csv_value("+1+1") == "'+1+1"
    assert _sanitize_csv_value("-1+1") == "'-1+1"
    assert _sanitize_csv_value("@SUM(A1)") == "'@SUM(A1)"
    assert _sanitize_csv_value("Normal Track") == "Normal Track"


def test_csv_export_row_cap_is_bounded():
    assert _MAX_CSV_EXPORT_ROWS <= 500
