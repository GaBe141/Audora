"""Tests for critical path, export, and command-execution hardening."""

from pathlib import Path

import pandas as pd
import pytest

from core.data_store import database_path_from_config
from core.utils import neutralize_csv_frame
from gui.app import _ALLOWED_DEMOS
from integrations.extended_platforms import safe_path_segment
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import SpotifyChartsAPI


def test_csv_formula_neutralization_maps_every_column():
    frame = pd.DataFrame(
        {
            "formula": ["=1+1", " =1+1", "\t@cmd", "safe"],
            "count": [1, 2, 3, 4],
        }
    )
    neutralized = neutralize_csv_frame(frame)
    assert neutralized["formula"].tolist() == ["'=1+1", "' =1+1", "'\t@cmd", "safe"]
    assert neutralized["count"].tolist() == [1, 2, 3, 4]


def test_config_database_path_rejects_absolute_and_escape():
    with pytest.raises(ValueError):
        database_path_from_config("/tmp/audora.db")
    with pytest.raises(ValueError):
        database_path_from_config("../outside.db")


def test_config_database_path_stays_under_project_root():
    resolved = Path(database_path_from_config("data/enhanced_music_trends.db"))
    project_root = Path(__file__).resolve().parent.parent
    assert resolved.is_relative_to(project_root)


def test_demo_allowlist_rejects_shell_payload():
    assert "rm -rf /" not in _ALLOWED_DEMOS
    assert "statistical" in _ALLOWED_DEMOS


def test_safe_path_segment_rejects_traversal():
    assert safe_path_segment("hiphopheads", label="subreddit") == "hiphopheads"
    with pytest.raises(ValueError):
        safe_path_segment("../etc", label="subreddit")


def test_musicbrainz_detail_requires_uuid():
    client = MusicBrainzAPI()
    with pytest.raises(ValueError, match="UUID"):
        client.get_artist_details("../../admin")


def test_spotify_chart_url_rejects_traversal_and_bad_dates():
    client = SpotifyChartsAPI()
    url = client._chart_url("regional", "US", "2024-01-02")
    assert url.endswith("/regional-us-daily/2024-01-02")
    with pytest.raises(ValueError):
        client._chart_url("regional", "../etc", "2024-01-02")
    with pytest.raises(ValueError):
        client._chart_url("regional", "global", "2024-13-40")
