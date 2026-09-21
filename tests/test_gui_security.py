"""Security tests for GUI command allowlisting and CSV export sanitization."""

import pandas as pd

from core.utils import neutralize_csv_dataframe
from gui.app import ALLOWED_DEMO_MODES, MAX_CSV_EXPORT_ROWS


def test_demo_modes_are_allowlisted():
    assert ALLOWED_DEMO_MODES == {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert "statistical; rm -rf /" not in ALLOWED_DEMO_MODES
    assert "--setup" not in ALLOWED_DEMO_MODES


def test_csv_export_neutralizes_formulas_and_caps_rows():
    df = pd.DataFrame(
        {
            "track_name": ["=CMD|'/c calc'!A0", "Safe Track"],
            "artist": ["+1+1", "Artist"],
        }
    )
    sanitized = neutralize_csv_dataframe(df)
    assert sanitized.loc[0, "track_name"].startswith("'=")
    assert sanitized.loc[0, "artist"].startswith("'+")
    assert sanitized.loc[1, "track_name"] == "Safe Track"
    assert MAX_CSV_EXPORT_ROWS <= 1000
