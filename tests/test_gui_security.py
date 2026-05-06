"""Security tests for Dash GUI helpers and callbacks."""

import importlib

import pandas as pd

gui_app = importlib.import_module("gui.app")


class DummyStore:
    """Minimal data-store stub for history search tests."""

    def get_trending_tracks(self, **_kwargs):
        return pd.DataFrame(
            [
                {
                    "artist": "a" * 120 + "X",
                    "track_name": "Track One",
                    "score": 90.0,
                    "metadata": {},
                },
                {
                    "artist": "Safe Artist",
                    "track_name": "Track Two",
                    "score": 80.0,
                    "metadata": {},
                },
            ]
        )


def test_history_artist_filter_uses_literal_search(monkeypatch):
    """Regex metacharacters should be treated as literal text to avoid ReDoS."""
    monkeypatch.setattr(gui_app, "_get_data_store", lambda: DummyStore())

    rows = gui_app.search_history(1, None, 0, 30, "(a+)+$")

    assert rows == []


def test_history_artist_filter_caps_input_length(monkeypatch):
    """Long hostile filters should be truncated before matching."""
    monkeypatch.setattr(gui_app, "_get_data_store", lambda: DummyStore())

    rows = gui_app.search_history(1, None, 0, 30, ("a" * 200) + "X")

    assert len(rows) == 1
    assert rows[0]["artist"] == "a" * 120 + "X"
