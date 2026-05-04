"""Security tests for GUI export helpers."""

import pandas as pd

from gui.app import _safe_csv_export


def test_csv_export_escapes_formula_prefixes():
    df = pd.DataFrame(
        {
            "track_name": ["=HYPERLINK(\"https://evil.example\")", "+SUM(1,1)", "Safe"],
            "artist": ["@cmd", "-10", "Normal"],
        }
    )

    csv_content = _safe_csv_export(df)

    assert "'=HYPERLINK" in csv_content
    assert "'+SUM" in csv_content
    assert "'@cmd" in csv_content
    assert "'-10" in csv_content
    assert "Normal" in csv_content
