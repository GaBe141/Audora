"""Deep analysis of genre evolution, age-related patterns, and seasonality in music taste."""

import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .auth import get_client

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def extract_release_decade(release_date: str) -> str:
    """Extract decade from release date string."""
    if not release_date or pd.isna(release_date):
        return "Unknown"

    # Handle different date formats
    year_match = re.search(r"(\d{4})", str(release_date))
    if year_match:
        year = int(year_match.group(1))
        decade = (year // 10) * 10
        return f"{decade}s"
    return "Unknown"


def categorize_genre_by_era(genre: str) -> dict[str, Any]:
    """Categorize genres by their typical emergence era and characteristics."""
    genre_lower = genre.lower()

    # Era classifications
    if any(term in genre_lower for term in ["rock", "blues", "folk", "country", "jazz"]):
        era = "Classic (40s-70s)"
        energy_level = "Medium"
    elif any(term in genre_lower for term in ["punk", "metal", "new wave", "disco"]):
        era = "Revolution (70s-80s)"
        energy_level = "High"
    elif any(term in genre_lower for term in ["grunge", "alternative", "indie", "britpop"]):
        era = "Alternative (80s-00s)"
        energy_level = "Medium-High"
    elif any(term in genre_lower for term in ["hip hop", "rap", "rnb", "r&b", "soul", "funk"]):
        era = "Urban (70s-Present)"
        energy_level = "Medium-High"
    elif any(term in genre_lower for term in ["electronic", "techno", "house", "edm", "synth"]):
        era = "Electronic (80s-Present)"
        energy_level = "High"
    elif any(term in genre_lower for term in ["pop", "dance", "mainstream"]):
        era = "Pop (50s-Present)"
        energy_level = "Medium"
    else:
        era = "Contemporary"
        energy_level = "Medium"

    # Seasonal associations (cultural/psychological)
    if any(term in genre_lower for term in ["chill", "ambient", "acoustic", "folk", "indie folk"]):
        seasonal_mood = "Autumn/Winter"
    elif any(term in genre_lower for term in ["dance", "pop", "electronic", "house", "edm"]):
        seasonal_mood = "Summer"
    elif any(term in genre_lower for term in ["rock", "alternative", "grunge", "punk"]):
        seasonal_mood = "Spring/Fall"
    else:
        seasonal_mood = "Year-round"

    return {"era": era, "energy_level": energy_level, "seasonal_mood": seasonal_mood}


def fetch_extended_listening_history() -> pd.DataFrame:
    """Fetch comprehensive listening data with temporal analysis."""
    sp = get_client()

    all_data = []

    # Get data across different time ranges
    time_ranges = ["short_term", "medium_term", "long_term"]
    range_weights = {
        "short_term": 1.0,
        "medium_term": 0.7,
        "long_term": 0.4,
    }  # Recent data weighted more

    for time_range in time_ranges:
        print(f"   📊 Analyzing {time_range} listening patterns...")

        # Top artists with genres
        artists = sp.current_user_top_artists(limit=50, time_range=time_range)
        for rank, artist in enumerate(artists["items"], start=1):
            for genre in artist.get("genres", []):
                genre_info = categorize_genre_by_era(genre)
                all_data.append(
                    {
                        "type": "artist",
                        "time_range": time_range,
                        "rank": rank,
                        "name": artist["name"],
                        "genre": genre,
                        "popularity": artist.get("popularity", 0),
                        "followers": artist.get("followers", {}).get("total", 0),
                        "weight": range_weights[time_range],
                        **genre_info,
                    }
                )

        # Top tracks with release dates
        tracks = sp.current_user_top_tracks(limit=50, time_range=time_range)
        for rank, track in enumerate(tracks["items"], start=1):
            release_date = track.get("album", {}).get("release_date", "")
            decade = extract_release_decade(release_date)

            # Get artist genres for this track
            artist_id = track.get("artists", [{}])[0].get("id")
            if artist_id:
                try:
                    artist_detail = sp.artist(artist_id)
                    track_genres = artist_detail.get("genres", [])
                except Exception:
                    track_genres = []
            else:
                track_genres = []

            for genre in track_genres:
                genre_info = categorize_genre_by_era(genre)
                all_data.append(
                    {
                        "type": "track",
                        "time_range": time_range,
                        "rank": rank,
                        "name": track["name"],
                        "artist": track.get("artists", [{}])[0].get("name"),
                        "genre": genre,
                        "popularity": track.get("popularity", 0),
                        "release_date": release_date,
                        "decade": decade,
                        "weight": range_weights[time_range],
                        **genre_info,
                    }
                )

    # Get recent listening with timestamps for seasonality
    print("   🕐 Analyzing recent temporal patterns...")
    recent = sp.current_user_recently_played(limit=50)
    for item in recent["items"]:
        played_at = pd.to_datetime(item["played_at"])
        track = item["track"]

        # Get artist info for genres
        artist_id = track.get("artists", [{}])[0].get("id")
        if artist_id:
            try:
                artist_detail = sp.artist(artist_id)
                track_genres = artist_detail.get("genres", [])
            except Exception:
                track_genres = []
        else:
            track_genres = []

        for genre in track_genres:
            genre_info = categorize_genre_by_era(genre)
            all_data.append(
                {
                    "type": "recent_play",
                    "played_at": played_at,
                    "hour": played_at.hour,
                    "day_of_week": played_at.strftime("%A"),
                    "month": played_at.strftime("%B"),
                    "season": get_season(played_at),
                    "name": track["name"],
                    "artist": track.get("artists", [{}])[0].get("name"),
                    "genre": genre,
                    "weight": 1.0,
                    **genre_info,
                }
            )

    return pd.DataFrame(all_data)


def get_season(date) -> str:
    """Determine season from date."""
    month = date.month
    if month in [12, 1, 2]:
        return "Winter"
    elif month in [3, 4, 5]:
        return "Spring"
    elif month in [6, 7, 8]:
        return "Summer"
    else:
        return "Autumn"


def analyze_generational_patterns(df: pd.DataFrame) -> dict:
    """Analyze how musical taste reflects generational patterns."""
    results = {}

    # Era preference analysis
    era_counts = (
        df.groupby(["time_range", "era"]).agg({"weight": "sum", "genre": "count"}).reset_index()
    )

    results["era_preference"] = era_counts

    # Decade analysis from track release dates
    decade_data = df[df["type"] == "track"].copy()
    if not decade_data.empty:
        decade_counts = (
            decade_data.groupby(["time_range", "decade"])
            .agg({"weight": "sum", "popularity": "mean"})
            .reset_index()
        )
        results["decade_preference"] = decade_counts

    # Energy level patterns
    energy_patterns = (
        df.groupby(["time_range", "energy_level"])
        .agg({"weight": "sum", "popularity": "mean"})
        .reset_index()
    )
    results["energy_patterns"] = energy_patterns

    return results


def analyze_seasonal_patterns(df: pd.DataFrame) -> dict:
    """Analyze seasonal and temporal patterns in music taste."""
    results = {}

    # Recent listening data only
    recent_data = df[df["type"] == "recent_play"].copy()

    if not recent_data.empty:
        # Seasonal genre preferences
        seasonal_genres = (
            recent_data.groupby(["season", "seasonal_mood"])
            .agg({"genre": "count", "weight": "sum"})
            .reset_index()
        )
        results["seasonal_preferences"] = seasonal_genres

        # Monthly patterns
        monthly_patterns = (
            recent_data.groupby(["month", "era"])
            .agg({"genre": "count", "weight": "sum"})
            .reset_index()
        )
        results["monthly_patterns"] = monthly_patterns

        # Time of day vs energy
        hourly_energy = (
            recent_data.groupby(["hour", "energy_level"])
            .agg({"genre": "count", "weight": "sum"})
            .reset_index()
        )
        results["hourly_energy"] = hourly_energy

    return results


def calculate_musical_maturity_score(df: pd.DataFrame) -> dict:
    """Calculate a 'musical maturity' score based on genre diversity and era preference."""

    # Genre diversity (Shannon entropy)
    genre_counts = df["genre"].value_counts()
    genre_probs = genre_counts / genre_counts.sum()
    genre_diversity = -np.sum(genre_probs * np.log2(genre_probs + 1e-10))

    # Era diversity
    era_counts = df["era"].value_counts()
    era_diversity = len(era_counts)

    # Preference for older music (sophistication proxy)
    classic_weight = df[df["era"].str.contains("Classic|Revolution")]["weight"].sum()
    total_weight = df["weight"].sum()
    classic_ratio = classic_weight / total_weight if total_weight > 0 else 0

    # Underground vs mainstream (lower popularity = more sophisticated?)
    avg_popularity = df["popularity"].mean()
    underground_score = (100 - avg_popularity) / 100  # Invert popularity

    # Composite maturity score
    maturity_score = (
        (genre_diversity / 10) * 0.3  # Normalize diversity
        + (era_diversity / 6) * 0.2  # Max ~6 eras
        + classic_ratio * 0.3  # Classic music preference
        + underground_score * 0.2  # Underground preference
    )

    return {
        "maturity_score": maturity_score,
        "genre_diversity": genre_diversity,
        "era_diversity": era_diversity,
        "classic_ratio": classic_ratio,
        "avg_popularity": avg_popularity,
        "underground_score": underground_score,
    }


def create_deep_analysis_report() -> dict:
    """Generate comprehensive deep analysis report."""
    print("🔬 Conducting deep musical taste analysis...")

    # Fetch extended data
    df = fetch_extended_listening_history()

    if df.empty:
        return {"error": "No data available for analysis"}

    print("🧬 Analyzing generational patterns...")
    generational_analysis = analyze_generational_patterns(df)

    print("🌅 Analyzing seasonal patterns...")
    seasonal_analysis = analyze_seasonal_patterns(df)

    print("🎓 Calculating musical maturity...")
    maturity_analysis = calculate_musical_maturity_score(df)

    # Save detailed dataset
    detailed_csv = DATA_DIR / "deep_music_analysis.csv"
    df.to_csv(detailed_csv, index=False)

    report = {
        "dataset": df,
        "generational_patterns": generational_analysis,
        "seasonal_patterns": seasonal_analysis,
        "maturity_analysis": maturity_analysis,
        "total_genres": df["genre"].nunique(),
        "total_data_points": len(df),
        "data_file": detailed_csv,
    }

    print(
        f"📊 Analysis complete! {len(df)} data points analyzed across {df['genre'].nunique()} genres"
    )

    return report
