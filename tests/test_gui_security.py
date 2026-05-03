"""Security tests for GUI data export helpers."""

from gui.security import escape_csv_formula


def test_escapes_spreadsheet_formula_prefixes():
    assert escape_csv_formula("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert escape_csv_formula("+SUM(1,2)") == "'+SUM(1,2)"
    assert escape_csv_formula("-10+20") == "'-10+20"
    assert escape_csv_formula("@HYPERLINK(\"https://example.com\")") == (
        "'@HYPERLINK(\"https://example.com\")"
    )


def test_leaves_safe_values_unchanged():
    assert escape_csv_formula("Track Name") == "Track Name"
    assert escape_csv_formula(42) == 42
