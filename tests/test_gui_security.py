"""Security tests for the prototyping GUI command and CSV helpers."""

import pytest

from core.utils import neutralize_csv_formula, neutralize_dataframe_formulas
from gui.app import _ALLOWED_DEMO_MODES, _safe_argv_token


class TestGuiCommandAllowlist:
    def test_demo_modes_match_cli_choices(self):
        assert frozenset(
            {"statistical", "trending", "multi_source", "platform", "all"}
        ) == _ALLOWED_DEMO_MODES

    def test_rejects_nul_and_non_string_argv(self):
        with pytest.raises(ValueError, match="Invalid command argument"):
            _safe_argv_token("foo\x00bar")
        with pytest.raises(ValueError, match="Invalid command argument"):
            _safe_argv_token(["--demo", "all"])


class TestCsvFormulaNeutralization:
    def test_prefixes_formula_cells(self):
        assert neutralize_csv_formula("=1+1") == "'=1+1"
        assert neutralize_csv_formula("+cmd") == "'+cmd"
        assert neutralize_csv_formula("safe") == "safe"
        assert neutralize_csv_formula(12) == 12

    def test_dataframe_copy_is_sanitized(self):
        import pandas as pd

        df = pd.DataFrame({"track": ["=CMD()", "ok"]})
        sanitized = neutralize_dataframe_formulas(df)
        assert sanitized.iloc[0]["track"] == "'=CMD()"
        assert df.iloc[0]["track"] == "=CMD()"
