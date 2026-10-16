"""Tests for critical path, export, and outbound-request hardening."""

from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

from core.data_store import EnhancedMusicDataStore, database_path_from_config
from core.utils import contained_output_path, neutralize_csv_frame, write_private_text
from gui.app import _demo_args
from integrations.extended_platforms import safe_path_segment
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import SpotifyChartsAPI


def test_csv_formula_neutralization_covers_string_dtype():
    frame = pd.DataFrame(
        {
            "formula": pd.Series(["=1+1"], dtype="string"),
            "spaced": pd.Series([" =1+1"], dtype="string"),
            "command": pd.Series(["\t@cmd"], dtype="string"),
            "plain": pd.Series(["hello"], dtype="string"),
        }
    )
    neutralized = neutralize_csv_frame(frame)
    assert neutralized.loc[0, "formula"] == "'=1+1"
    assert neutralized.loc[0, "spaced"] == "' =1+1"
    assert neutralized.loc[0, "command"] == "'\t@cmd"
    assert neutralized.loc[0, "plain"] == "hello"


def test_database_config_path_rejects_absolute_and_parent_segments(tmp_path: Path):
    with pytest.raises(ValueError, match="relative"):
        database_path_from_config(str(tmp_path / "music.db"))
    with pytest.raises(ValueError, match="parent"):
        database_path_from_config("../music.db")


def test_database_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real.db"
    real.write_bytes(b"")
    link = tmp_path / "link.db"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        EnhancedMusicDataStore(db_path=str(link), backup_dir=str(tmp_path / "backups"))


def test_output_path_rejects_escape():
    with pytest.raises(ValueError, match="parent"):
        contained_output_path("../secrets.csv")


def test_private_write_refuses_symlink(tmp_path: Path):
    target = tmp_path / "real.txt"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symlink"):
        write_private_text(link, "overwrite")
    assert target.read_text(encoding="utf-8") == "keep"


def test_demo_modes_are_allowlisted():
    command = _demo_args("statistical")
    assert command[-2:] == ["--demo", "statistical"]
    with pytest.raises(ValueError, match="Unknown demo"):
        _demo_args("rm -rf /")


def test_chart_url_rejects_path_injection():
    api = SpotifyChartsAPI()
    url = api._chart_url("regional", "US", "2024-01-15")
    assert url.endswith("/regional-us-daily/2024-01-15")
    with pytest.raises(ValueError, match="country"):
        api._chart_url("regional", "../admin", "2024-01-15")
    with pytest.raises(ValueError, match="date"):
        api._chart_url("regional", "us", "2024-13-40")


def test_musicbrainz_detail_lookup_requires_uuid():
    api = MusicBrainzAPI()
    with pytest.raises(ValueError, match="UUID"):
        api.get_artist_details("../../admin")
    with pytest.raises(ValueError, match="UUID"):
        api.get_artist_releases("not-a-uuid")


def test_safe_path_segment_rejects_traversal():
    assert safe_path_segment("hiphopheads", field="subreddit") == "hiphopheads"
    with pytest.raises(ValueError, match="subreddit"):
        safe_path_segment("../etc", field="subreddit")


def test_chart_date_must_be_real():
    api = SpotifyChartsAPI()
    yesterday = (datetime.now()).strftime("%Y-%m-%d")
    assert yesterday in api._chart_url("viral", "global", yesterday)
