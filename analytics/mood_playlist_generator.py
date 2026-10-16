"""
Mood-Based Playlist Generator
=============================

Intelligent playlist generation based on audio features and mood analysis.
Uses Spotify audio features (valence, energy, tempo, danceability, etc.)
to categorize tracks into mood-based playlists.

Mood Categories:
    😊 Happy & Upbeat - High valence, high energy
    😌 Chill & Relaxed - Low energy, moderate valence
    💪 Energetic & Intense - Very high energy, high tempo
    😔 Melancholic & Reflective - Low valence, low energy
    🎯 Focus & Concentration - Mid energy, instrumental, low valence variance
    🕺 Party & Dance - High danceability, high energy, high tempo
    🌙 Late Night Vibes - Low energy, smooth, moderate tempo
    🌅 Morning Energy - Rising energy, positive valence, moderate tempo
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import numpy as np
import pandas as pd

from core.utils import confine_child_path, confine_path, load_dataframe, save_report


class MoodCategory(Enum):
    """Enumeration of available mood categories."""

    HAPPY_UPBEAT = "😊 Happy & Upbeat"
    CHILL_RELAXED = "😌 Chill & Relaxed"
    ENERGETIC_INTENSE = "💪 Energetic & Intense"
    MELANCHOLIC = "😔 Melancholic & Reflective"
    FOCUS = "🎯 Focus & Concentration"
    PARTY_DANCE = "🕺 Party & Dance"
    LATE_NIGHT = "🌙 Late Night Vibes"
    MORNING_ENERGY = "🌅 Morning Energy"


@dataclass
class AudioFeatures:
    """Container for Spotify audio features."""

    valence: float  # 0-1, musical positiveness
    energy: float  # 0-1, intensity and activity
    danceability: float  # 0-1, how suitable for dancing
    tempo: float  # BPM
    acousticness: float  # 0-1, acoustic vs electronic
    instrumentalness: float  # 0-1, presence of vocals
    speechiness: float  # 0-1, presence of spoken words
    liveness: float  # 0-1, presence of audience
    loudness: float  # dB, typically -60 to 0


@dataclass
class MoodProfile:
    """Mood profile with feature ranges and weights."""

    valence_range: tuple[float, float]
    energy_range: tuple[float, float]
    tempo_range: tuple[float, float]
    danceability_min: float = 0.0
    instrumentalness_max: float = 1.0
    weights: dict[str, float] = None  # Feature importance weights

    def __post_init__(self):
        if self.weights is None:
            self.weights = {"valence": 1.0, "energy": 1.0, "tempo": 0.5, "danceability": 0.7}


class MoodPlaylistGenerator:
    """Generate mood-based playlists from music collection."""

    # Mood profile definitions
    MOOD_PROFILES: dict[MoodCategory, MoodProfile] = {
        MoodCategory.HAPPY_UPBEAT: MoodProfile(
            valence_range=(0.6, 1.0),
            energy_range=(0.6, 1.0),
            tempo_range=(100, 180),
            danceability_min=0.5,
            weights={"valence": 1.5, "energy": 1.2, "tempo": 0.8, "danceability": 1.0},
        ),
        MoodCategory.CHILL_RELAXED: MoodProfile(
            valence_range=(0.3, 0.7),
            energy_range=(0.0, 0.5),
            tempo_range=(60, 110),
            danceability_min=0.0,
            weights={"energy": 1.5, "valence": 0.8, "tempo": 1.0, "danceability": 0.5},
        ),
        MoodCategory.ENERGETIC_INTENSE: MoodProfile(
            valence_range=(0.4, 1.0),
            energy_range=(0.8, 1.0),
            tempo_range=(130, 200),
            danceability_min=0.4,
            weights={"energy": 2.0, "tempo": 1.5, "valence": 0.5, "danceability": 1.0},
        ),
        MoodCategory.MELANCHOLIC: MoodProfile(
            valence_range=(0.0, 0.4),
            energy_range=(0.0, 0.5),
            tempo_range=(60, 120),
            danceability_min=0.0,
            weights={"valence": 2.0, "energy": 1.2, "tempo": 0.6, "danceability": 0.3},
        ),
        MoodCategory.FOCUS: MoodProfile(
            valence_range=(0.2, 0.6),
            energy_range=(0.3, 0.7),
            tempo_range=(80, 130),
            danceability_min=0.0,
            instrumentalness_max=1.0,
            weights={"energy": 1.0, "valence": 0.5, "tempo": 0.8, "danceability": 0.3},
        ),
        MoodCategory.PARTY_DANCE: MoodProfile(
            valence_range=(0.5, 1.0),
            energy_range=(0.7, 1.0),
            tempo_range=(110, 140),
            danceability_min=0.7,
            weights={"danceability": 2.0, "energy": 1.5, "valence": 1.0, "tempo": 1.2},
        ),
        MoodCategory.LATE_NIGHT: MoodProfile(
            valence_range=(0.2, 0.6),
            energy_range=(0.2, 0.5),
            tempo_range=(70, 100),
            danceability_min=0.0,
            weights={"energy": 1.5, "valence": 1.0, "tempo": 1.0, "danceability": 0.5},
        ),
        MoodCategory.MORNING_ENERGY: MoodProfile(
            valence_range=(0.5, 0.9),
            energy_range=(0.5, 0.8),
            tempo_range=(100, 140),
            danceability_min=0.4,
            weights={"valence": 1.5, "energy": 1.3, "tempo": 0.9, "danceability": 0.8},
        ),
    }

    def __init__(self, data_dir: str = "data"):
        """Initialize the mood playlist generator."""
        self.data_dir = confine_path(data_dir)
        self.tracks_df: pd.DataFrame | None = None
        self.mood_playlists: dict[MoodCategory, list[dict[str, Any]]] = {}

    def load_tracks(self, filename: str = "simple_top_tracks.csv") -> pd.DataFrame:
        """Load track data from CSV using centralized utility."""
        filepath = confine_child_path(self.data_dir, filename)

        # Define expected columns
        expected_cols = [
            "track_name",
            "artist_name",
            "popularity",
            "valence",
            "energy",
            "danceability",
            "tempo",
        ]

        df = load_dataframe(filepath, default_empty=True)

        if df.empty:
            print(f"⚠️  File not found or empty: {filepath}")
            # Return empty DataFrame with expected columns
            return pd.DataFrame(columns=expected_cols)

        self.tracks_df = df
        print(f"✅ Loaded {len(self.tracks_df)} tracks from {filename}")
        return self.tracks_df

    def generate_synthetic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate synthetic audio features for tracks that don't have them.
        Uses popularity and other available data to make reasonable estimates.
        """
        if df.empty:
            return df

        df = df.copy()

        # Generate features if they don't exist
        feature_columns = [
            "valence",
            "energy",
            "danceability",
            "tempo",
            "acousticness",
            "instrumentalness",
            "speechiness",
            "liveness",
            "loudness",
        ]

        for col in feature_columns:
            if col not in df.columns:
                if col == "tempo":
                    # Tempo: 60-180 BPM, normally distributed around 120
                    df[col] = np.random.normal(120, 25, len(df))
                    df[col] = df[col].clip(60, 200)
                elif col == "loudness":
                    # Loudness: -20 to -5 dB
                    df[col] = np.random.uniform(-20, -5, len(df))
                else:
                    # Other features: 0-1 range with some clustering
                    base = np.random.beta(2, 2, len(df))

                    # Add some correlation with popularity if available
                    if "popularity" in df.columns:
                        pop_normalized = df["popularity"] / 100.0

                        if col == "energy":
                            df[col] = base * 0.7 + pop_normalized * 0.3
                        elif col == "valence":
                            df[col] = base * 0.8 + pop_normalized * 0.2
                        elif col == "danceability":
                            df[col] = base * 0.7 + pop_normalized * 0.3
                        else:
                            df[col] = base
                    else:
                        df[col] = base

        return df

    def calculate_mood_score(
        self, track_features: AudioFeatures, mood_profile: MoodProfile
    ) -> float:
        """
        Calculate how well a track matches a mood profile.
        Returns a score from 0-100.
        """
        score = 0.0
        max_score = 0.0

        # Valence score
        if mood_profile.valence_range[0] <= track_features.valence <= mood_profile.valence_range[1]:
            # Perfect match
            valence_score = 1.0
        else:
            # Penalize based on distance from range
            if track_features.valence < mood_profile.valence_range[0]:
                distance = mood_profile.valence_range[0] - track_features.valence
            else:
                distance = track_features.valence - mood_profile.valence_range[1]
            valence_score = max(0, 1 - distance * 2)  # Steep penalty

        weight = mood_profile.weights.get("valence", 1.0)
        score += valence_score * weight
        max_score += weight

        # Energy score
        if mood_profile.energy_range[0] <= track_features.energy <= mood_profile.energy_range[1]:
            energy_score = 1.0
        else:
            if track_features.energy < mood_profile.energy_range[0]:
                distance = mood_profile.energy_range[0] - track_features.energy
            else:
                distance = track_features.energy - mood_profile.energy_range[1]
            energy_score = max(0, 1 - distance * 2)

        weight = mood_profile.weights.get("energy", 1.0)
        score += energy_score * weight
        max_score += weight

        # Tempo score
        if mood_profile.tempo_range[0] <= track_features.tempo <= mood_profile.tempo_range[1]:
            tempo_score = 1.0
        else:
            if track_features.tempo < mood_profile.tempo_range[0]:
                distance = (mood_profile.tempo_range[0] - track_features.tempo) / 50
            else:
                distance = (track_features.tempo - mood_profile.tempo_range[1]) / 50
            tempo_score = max(0, 1 - distance)

        weight = mood_profile.weights.get("tempo", 0.5)
        score += tempo_score * weight
        max_score += weight

        # Danceability score
        if track_features.danceability >= mood_profile.danceability_min:
            danceability_score = track_features.danceability
        else:
            danceability_score = track_features.danceability * 0.5

        weight = mood_profile.weights.get("danceability", 0.7)
        score += danceability_score * weight
        max_score += weight

        # Normalize to 0-100
        final_score = (score / max_score) * 100 if max_score > 0 else 0
        return final_score

    def generate_mood_playlists(
        self, min_score: float = 60.0, max_tracks_per_mood: int = 50
    ) -> dict[MoodCategory, list[dict[str, Any]]]:
        """
        Generate playlists for all mood categories.

        Args:
            min_score: Minimum mood match score (0-100) to include track
            max_tracks_per_mood: Maximum tracks per playlist

        Returns:
            Dictionary mapping mood categories to track lists
        """
        if self.tracks_df is None or self.tracks_df.empty:
            print("⚠️  No tracks loaded. Call load_tracks() first.")
            return {}

        # Ensure we have audio features
        df = self.generate_synthetic_features(self.tracks_df)

        print("\n🎵 Generating mood-based playlists...")
        print(f"   Analyzing {len(df)} tracks across {len(self.MOOD_PROFILES)} moods")
        print(f"   Minimum mood score: {min_score}/100")

        self.mood_playlists = {}

        for mood, profile in self.MOOD_PROFILES.items():
            mood_tracks = []

            for idx, row in df.iterrows():
                # Create AudioFeatures object
                features = AudioFeatures(
                    valence=row.get("valence", 0.5),
                    energy=row.get("energy", 0.5),
                    danceability=row.get("danceability", 0.5),
                    tempo=row.get("tempo", 120),
                    acousticness=row.get("acousticness", 0.5),
                    instrumentalness=row.get("instrumentalness", 0.1),
                    speechiness=row.get("speechiness", 0.1),
                    liveness=row.get("liveness", 0.2),
                    loudness=row.get("loudness", -10),
                )

                # Calculate mood score
                score = self.calculate_mood_score(features, profile)

                if score >= min_score:
                    track_info = {
                        "track_name": row.get("track_name", row.get("name", "Unknown")),
                        "artist": row.get("artist_name", row.get("artist", "Unknown")),
                        "mood_score": score,
                        "features": {
                            "valence": features.valence,
                            "energy": features.energy,
                            "danceability": features.danceability,
                            "tempo": features.tempo,
                        },
                    }
                    mood_tracks.append(track_info)

            # Sort by mood score and limit
            mood_tracks.sort(key=lambda x: x["mood_score"], reverse=True)
            mood_tracks = mood_tracks[:max_tracks_per_mood]

            self.mood_playlists[mood] = mood_tracks

            print(f"   {mood.value:<30} {len(mood_tracks):>3} tracks")

        return self.mood_playlists

    def get_playlist(self, mood: MoodCategory) -> list[dict[str, Any]]:
        """Get playlist for a specific mood."""
        return self.mood_playlists.get(mood, [])

    def print_playlist(self, mood: MoodCategory, max_tracks: int = 10):
        """Print a formatted playlist for a specific mood."""
        tracks = self.get_playlist(mood)

        if not tracks:
            print(f"\n{mood.value}")
            print("=" * 50)
            print("No tracks found for this mood.")
            return

        print(f"\n{mood.value}")
        print("=" * 50)

        for i, track in enumerate(tracks[:max_tracks], 1):
            print(f"{i:2}. {track['track_name'][:35]:<35} - {track['artist'][:20]:<20}")
            print(
                f"    Mood Score: {track['mood_score']:5.1f}/100 | "
                f"Energy: {track['features']['energy']:.2f} | "
                f"Valence: {track['features']['valence']:.2f} | "
                f"BPM: {track['features']['tempo']:.0f}"
            )

        if len(tracks) > max_tracks:
            print(f"    ... and {len(tracks) - max_tracks} more tracks")

    def export_playlist(self, mood: MoodCategory, output_file: str | None = None) -> str:
        """
        Export playlist to JSON file using centralized utility.

        Returns:
            Path to exported file
        """
        tracks = self.get_playlist(mood)

        playlist_data = {
            "mood": mood.value,
            "mood_category": mood.name,
            "generated_at": datetime.now().isoformat(),
            "track_count": len(tracks),
            "tracks": tracks,
        }

        # Use save_report utility
        saved_path = save_report(
            playlist_data,
            filename=output_file,
            prefix=f"playlist_{mood.name.lower()}",
            output_dir=str(self.data_dir / "playlists"),
            add_timestamp=False,  # Already added in playlist_data
        )

        print(f"✅ Playlist exported: {saved_path}")
        return str(saved_path)

    def get_mood_statistics(self) -> dict[str, Any]:
        """Get statistics about generated playlists."""
        stats = {
            "total_moods": len(self.mood_playlists),
            "total_tracks": sum(len(tracks) for tracks in self.mood_playlists.values()),
            "moods": {},
        }

        for mood, tracks in self.mood_playlists.items():
            if tracks:
                scores = [t["mood_score"] for t in tracks]
                stats["moods"][mood.value] = {
                    "track_count": len(tracks),
                    "avg_score": np.mean(scores),
                    "min_score": np.min(scores),
                    "max_score": np.max(scores),
                }

        return stats


def main():
    """Demo of mood playlist generator."""
    print("🎵 AUDORA MOOD-BASED PLAYLIST GENERATOR")
    print("=" * 60)

    # Initialize generator
    generator = MoodPlaylistGenerator()

    # Load tracks
    generator.load_tracks()

    # Generate playlists
    generator.generate_mood_playlists(min_score=55.0)

    # Show statistics
    print("\n📊 PLAYLIST STATISTICS")
    print("-" * 60)
    stats = generator.get_mood_statistics()
    print(f"Total playlists: {stats['total_moods']}")
    print(f"Total tracks across all playlists: {stats['total_tracks']}")

    # Print each playlist
    print("\n🎧 GENERATED PLAYLISTS")
    print("=" * 60)

    for mood in MoodCategory:
        generator.print_playlist(mood, max_tracks=5)

    # Export a few playlists
    print("\n💾 EXPORTING PLAYLISTS")
    print("-" * 60)
    generator.export_playlist(MoodCategory.HAPPY_UPBEAT)
    generator.export_playlist(MoodCategory.CHILL_RELAXED)
    generator.export_playlist(MoodCategory.FOCUS)

    print("\n✨ Mood playlist generation complete!")


if __name__ == "__main__":
    main()
