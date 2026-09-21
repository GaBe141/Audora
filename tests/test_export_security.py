"""Tests for CSV formula neutralization and export path confinement."""

import pandas as pd
import pytest

from core.utils import confine_to_project, neutralize_csv_formulas


def test_neutralize_csv_formulas_prefixes_formula_cells():
    frame = pd.DataFrame({"title": ["=1+1", "safe", "+cmd"], "score": [1, 2, 3]})
    sanitized = neutralize_csv_formulas(frame)
    assert sanitized["title"].tolist() == ["'=1+1", "safe", "'+cmd"]
    assert sanitized["score"].tolist() == [1, 2, 3]


def test_confine_to_project_rejects_escape(tmp_path):
    outside = tmp_path / "outside.csv"
    with pytest.raises(ValueError, match="inside"):
        confine_to_project(outside)
