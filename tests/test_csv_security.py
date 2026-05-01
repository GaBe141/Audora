"""Regression tests for safe CSV exports."""

import io

import pandas as pd

from core.utils import neutralize_csv_formula_value, write_safe_csv


def test_neutralize_csv_formula_value_prefixes_spreadsheet_formulas():
    assert neutralize_csv_formula_value("=HYPERLINK('https://attacker.test')").startswith("'=")
    assert neutralize_csv_formula_value("+SUM(1,2)").startswith("'+")
    assert neutralize_csv_formula_value("-10+cmd").startswith("'-")
    assert neutralize_csv_formula_value("@malicious").startswith("'@")
    assert neutralize_csv_formula_value("\t=hidden").startswith("'\t")
    assert neutralize_csv_formula_value("\r=hidden").startswith("'\r")
    assert neutralize_csv_formula_value("safe") == "safe"
    assert neutralize_csv_formula_value(42) == 42


def test_write_safe_csv_neutralizes_text_cells():
    buf = io.StringIO()
    df = pd.DataFrame(
        {
            "track_name": ["=HYPERLINK('https://attacker.test')", "Safe Song"],
            "score": [99, -1],
        }
    )

    write_safe_csv(df, buf, index=False)

    csv_text = buf.getvalue()
    assert "'=HYPERLINK" in csv_text
    assert "\n=HYPERLINK" not in csv_text
    assert "Safe Song" in csv_text
