"""Security tests for CSV export formula escaping."""

import pandas as pd

from core.utils import sanitize_dataframe_for_csv, save_dataframe


class TestCsvFormulaSanitization:
    """Ensure exported CSV data cannot become spreadsheet formulas."""

    def test_sanitize_dataframe_escapes_formula_prefixes(self):
        df = pd.DataFrame(
            {
                "track_name": ["=cmd|'/C calc'!A0", "+SUM(1,2)", "-10", "@hidden", "safe"],
                "score": [1, 2, 3, 4, 5],
            }
        )

        sanitized = sanitize_dataframe_for_csv(df)

        assert sanitized["track_name"].tolist() == [
            "'=cmd|'/C calc'!A0",
            "'+SUM(1,2)",
            "'-10",
            "'@hidden",
            "safe",
        ]
        assert sanitized["score"].tolist() == [1, 2, 3, 4, 5]
        assert df["track_name"].iloc[0] == "=cmd|'/C calc'!A0"

    def test_sanitize_dataframe_escapes_leading_whitespace_formula(self):
        df = pd.DataFrame({"artist": [" \t=IMPORTXML(\"http://example.com\", \"//a\")"]})

        sanitized = sanitize_dataframe_for_csv(df)

        assert sanitized["artist"].iloc[0].startswith("'")

    def test_save_dataframe_sanitizes_csv_output(self, tmp_path):
        output_path = tmp_path / "export.csv"
        df = pd.DataFrame({"artist": ["=malicious"], "score": [99]})

        save_dataframe(df, output_path)

        csv_text = output_path.read_text(encoding="utf-8")
        assert "'=malicious" in csv_text
