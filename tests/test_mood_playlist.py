"""Tests for analytics mood_playlist_generator (MoodCategory, MoodPlaylistGenerator, score consistency)."""

import pandas as pd

from analytics.mood_playlist_generator import (
    MoodCategory,
    MoodPlaylistGenerator,
    MoodProfile,
)


def _make_tracks_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal tracks DataFrame with audio feature columns."""
    defaults = {
        "track_name": "Track",
        "artist_name": "Artist",
        "valence": 0.5,
        "energy": 0.5,
        "danceability": 0.5,
        "tempo": 120.0,
    }
    data = []
    for r in rows:
        row = dict(defaults)
        row.update(r)
        data.append(row)
    return pd.DataFrame(data)


class TestMoodCategoryAndProfile:
    """Smoke tests for MoodCategory and MOOD_PROFILES."""

    def test_mood_profiles_has_all_categories(self):
        for mood in MoodCategory:
            assert mood in MoodPlaylistGenerator.MOOD_PROFILES
            profile = MoodPlaylistGenerator.MOOD_PROFILES[mood]
            assert isinstance(profile, MoodProfile)
            assert hasattr(profile, "valence_range")
            assert hasattr(profile, "energy_range")


class TestMoodPlaylistGenerator:
    """Tests for MoodPlaylistGenerator with fixture DataFrame."""

    def test_generate_mood_playlists_returns_dict_of_lists(self):
        generator = MoodPlaylistGenerator()
        generator.tracks_df = _make_tracks_df(
            [
                {"track_name": "A", "valence": 0.8, "energy": 0.8, "danceability": 0.7},
                {"track_name": "B", "valence": 0.3, "energy": 0.3},
            ]
        )
        playlists = generator.generate_mood_playlists(min_score=0.0, max_tracks_per_mood=50)
        assert isinstance(playlists, dict)
        for mood, tracks in playlists.items():
            assert isinstance(mood, MoodCategory)
            assert isinstance(tracks, list)
            for t in tracks:
                assert "track_name" in t
                assert "mood_score" in t

    def test_at_least_one_playlist_has_tracks_with_high_min_score(self):
        generator = MoodPlaylistGenerator()
        # High valence/energy -> should match HAPPY_UPBEAT or similar
        generator.tracks_df = _make_tracks_df(
            [
                {
                    "track_name": "Happy",
                    "valence": 0.9,
                    "energy": 0.85,
                    "danceability": 0.8,
                    "tempo": 120,
                },
            ]
        )
        playlists = generator.generate_mood_playlists(min_score=50.0)
        total = sum(len(tracks) for tracks in playlists.values())
        assert total >= 1

    def test_score_consistency_same_track_same_score(self):
        df = _make_tracks_df(
            [
                {"track_name": "Same", "valence": 0.7, "energy": 0.6, "danceability": 0.6},
            ]
        )
        gen1 = MoodPlaylistGenerator()
        gen1.tracks_df = df.copy()
        playlists1 = gen1.generate_mood_playlists(min_score=0.0)
        gen2 = MoodPlaylistGenerator()
        gen2.tracks_df = df.copy()
        playlists2 = gen2.generate_mood_playlists(min_score=0.0)
        for mood in MoodCategory:
            t1 = playlists1.get(mood, [])
            t2 = playlists2.get(mood, [])
            if t1 and t2:
                assert t1[0]["mood_score"] == t2[0]["mood_score"]

    def test_empty_tracks_returns_empty_dict(self):
        generator = MoodPlaylistGenerator()
        generator.tracks_df = pd.DataFrame()
        playlists = generator.generate_mood_playlists(min_score=0.0)
        assert playlists == {}
