"""Simple surprise visualizations that work with basic Spotify API permissions."""

import warnings
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from core.utils import save_dataframe

from .fetch import fetch_recently_played, fetch_top_artists, fetch_top_tracks

warnings.filterwarnings("ignore")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def plot_artist_popularity_vs_rank(time_ranges=["short_term", "medium_term", "long_term"]) -> Path:
    """Plot how artist popularity correlates with your personal ranking across time."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1"]
    labels = ["Recent (~4 weeks)", "Medium (~6 months)", "Long (~years)"]

    for i, (time_range, color, label) in enumerate(zip(time_ranges, colors, labels, strict=False)):
        df = fetch_top_artists(limit=20, time_range=time_range)
        if not df.empty:
            axes[i].scatter(df["rank"], df["popularity"], color=color, alpha=0.7, s=100)
            axes[i].set_xlabel("Your Personal Rank")
            axes[i].set_ylabel("Spotify Popularity")
            axes[i].set_title(f"{label}")
            axes[i].grid(True, alpha=0.3)
            axes[i].set_xlim(0, 21)
            axes[i].set_ylim(0, 100)

            # Add trend line
            if len(df) > 5:
                z = np.polyfit(df["rank"], df["popularity"], 1)
                p = np.poly1d(z)
                axes[i].plot(df["rank"], p(df["rank"]), "--", color="darkgray", alpha=0.8)

    plt.suptitle("🎯 Do You Like Mainstream or Underground Artists?", size=16, y=1.02)
    plt.tight_layout()

    out_path = DATA_DIR / "popularity_vs_rank.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_listening_clock() -> Path:
    """Create a circular clock showing when you listen to music."""
    df = fetch_recently_played(limit=50)
    if df.empty:
        raise ValueError("No recent listening data")

    # Extract hour and count plays
    df["hour"] = df["played_at"].dt.hour
    hourly_counts = df["hour"].value_counts().sort_index()

    # Create circular plot
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection="polar"))

    # Convert hours to radians (24 hours = 2π)
    theta = np.linspace(0, 2 * np.pi, 24, endpoint=False)

    # Map hours to counts (fill missing hours with 0)
    counts = [hourly_counts.get(hour, 0) for hour in range(24)]

    # Create bar chart
    ax.bar(theta, counts, width=2 * np.pi / 24, alpha=0.7, color="#1DB954")

    # Customize
    ax.set_theta_zero_location("N")  # Start at top (midnight)
    ax.set_theta_direction(-1)  # Clockwise
    ax.set_xticks(theta)
    ax.set_xticklabels([f"{hour:02d}:00" for hour in range(24)])
    ax.set_ylim(0, max(counts) * 1.1)
    ax.set_title("🕐 Your Music Listening Clock", size=16, pad=20)

    # Add day/night background
    night_hours = list(range(22, 24)) + list(range(0, 6))
    for hour in night_hours:
        ax.bar(theta[hour], max(counts) * 1.1, width=2 * np.pi / 24, alpha=0.1, color="navy")

    plt.tight_layout()
    out_path = DATA_DIR / "listening_clock.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_top_artist_genres() -> Path:
    """Create a sunburst-style genre analysis from top artists."""
    # Get artists from all time ranges
    all_artists = []
    time_ranges = ["short_term", "medium_term", "long_term"]

    for time_range in time_ranges:
        df = fetch_top_artists(limit=20, time_range=time_range)
        df["time_range"] = time_range
        all_artists.append(df)

    combined_df = pd.concat(all_artists, ignore_index=True)

    # Parse genres
    genre_data = []
    for _, row in combined_df.iterrows():
        genres = [g.strip() for g in row["genres"].split(",") if g.strip()]
        for genre in genres:
            genre_data.append(
                {"genre": genre, "time_range": row["time_range"], "artist": row["name"]}
            )

    genre_df = pd.DataFrame(genre_data)

    if genre_df.empty:
        raise ValueError("No genre data found")

    # Get top genres
    top_genres = genre_df["genre"].value_counts().head(12)

    # Create subplot with genre counts by time range
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    # Overall genre pie chart
    colors = plt.cm.Set3(np.linspace(0, 1, len(top_genres)))
    wedges, texts, autotexts = ax1.pie(
        top_genres.values, labels=top_genres.index, autopct="%1.1f%%", colors=colors, startangle=90
    )
    ax1.set_title("🎭 Your Genre Distribution", size=14)

    # Adjust text size
    for text in texts:
        text.set_fontsize(9)
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontweight("bold")
        autotext.set_fontsize(8)

    # Genre evolution over time
    genre_time = genre_df.groupby(["time_range", "genre"]).size().reset_index(name="count")
    top_genre_names = top_genres.head(8).index
    genre_time_filtered = genre_time[genre_time["genre"].isin(top_genre_names)]

    pivot_data = genre_time_filtered.pivot(
        index="time_range", columns="genre", values="count"
    ).fillna(0)
    time_order = ["short_term", "medium_term", "long_term"]
    pivot_data = pivot_data.reindex(time_order)

    # Stacked bar chart
    pivot_data.plot(kind="bar", stacked=True, ax=ax2, colormap="Set3")
    ax2.set_title("🕰️ Genre Evolution Over Time", size=14)
    ax2.set_xlabel("Time Range")
    ax2.set_ylabel("Genre Occurrences")
    ax2.set_xticklabels(["Recent", "Medium", "Long"], rotation=0)
    ax2.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize=8)

    plt.tight_layout()
    out_path = DATA_DIR / "genre_analysis.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

    # Save genre data
    save_dataframe(genre_df, DATA_DIR / "genre_data.csv")

    return out_path


def plot_track_length_distribution() -> Path:
    """Analyze the length of tracks you prefer."""
    time_ranges = ["short_term", "medium_term", "long_term"]
    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1"]
    labels = ["Recent", "Medium", "Long"]

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.ravel()

    all_durations = []

    for i, (time_range, color, label) in enumerate(zip(time_ranges, colors, labels, strict=False)):
        df = fetch_top_tracks(limit=20, time_range=time_range)
        if not df.empty and "duration_ms" in df.columns:
            # Convert to minutes
            df["duration_min"] = df["duration_ms"] / (1000 * 60)
            all_durations.extend(df["duration_min"].tolist())

            # Histogram
            axes[i].hist(df["duration_min"], bins=8, color=color, alpha=0.7, edgecolor="black")
            axes[i].set_title(f"🎵 Track Length - {label}")
            axes[i].set_xlabel("Duration (minutes)")
            axes[i].set_ylabel("Number of tracks")
            axes[i].grid(True, alpha=0.3)

    # Combined distribution
    if all_durations:
        axes[3].hist(all_durations, bins=15, color="purple", alpha=0.7, edgecolor="black")
        axes[3].set_title("🎼 Overall Track Length Distribution")
        axes[3].set_xlabel("Duration (minutes)")
        axes[3].set_ylabel("Number of tracks")
        axes[3].grid(True, alpha=0.3)

        # Add statistics
        mean_duration = np.mean(all_durations)
        axes[3].axvline(
            mean_duration, color="red", linestyle="--", label=f"Mean: {mean_duration:.1f} min"
        )
        axes[3].legend()

    plt.suptitle("⏱️ How Long Are Your Favorite Songs?", size=16)
    plt.tight_layout()

    out_path = DATA_DIR / "track_length_analysis.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_discovery_timeline() -> Path:
    """Plot your music discovery timeline using recently played tracks."""
    df = fetch_recently_played(limit=50)
    if df.empty:
        raise ValueError("No recent listening data")

    # Group by date and count unique tracks/artists
    df["date"] = df["played_at"].dt.date
    daily_stats = (
        df.groupby("date")
        .agg({"track_name": "nunique", "artist": "nunique"})
        .rename(columns={"track_name": "unique_tracks", "artist": "unique_artists"})
    )

    # Create timeline plot
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

    # Plot unique tracks per day
    ax1.plot(
        daily_stats.index,
        daily_stats["unique_tracks"],
        marker="o",
        linewidth=2,
        color="#1DB954",
        markersize=6,
    )
    ax1.set_ylabel("Unique Tracks")
    ax1.set_title("🎵 Your Music Discovery Timeline")
    ax1.grid(True, alpha=0.3)
    ax1.fill_between(daily_stats.index, daily_stats["unique_tracks"], alpha=0.3, color="#1DB954")

    # Plot unique artists per day
    ax2.plot(
        daily_stats.index,
        daily_stats["unique_artists"],
        marker="s",
        linewidth=2,
        color="#FF6B6B",
        markersize=6,
    )
    ax2.set_ylabel("Unique Artists")
    ax2.set_xlabel("Date")
    ax2.grid(True, alpha=0.3)
    ax2.fill_between(daily_stats.index, daily_stats["unique_artists"], alpha=0.3, color="#FF6B6B")

    # Rotate x-axis labels
    plt.xticks(rotation=45)
    plt.tight_layout()

    out_path = DATA_DIR / "discovery_timeline.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def generate_simple_surprise_visualizations():
    """Generate surprise visualizations using basic API data."""
    print("🎨 Creating surprise visualizations from your Spotify data...")
    generated_files = []

    try:
        print("📊 1. Analyzing mainstream vs underground taste...")
        popularity_path = plot_artist_popularity_vs_rank()
        generated_files.append(popularity_path)
        print(f"   ✅ Saved: {popularity_path.name}")

        print("🕐 2. Creating your listening clock...")
        clock_path = plot_listening_clock()
        generated_files.append(clock_path)
        print(f"   ✅ Saved: {clock_path.name}")

        print("🎭 3. Exploring your genre landscape...")
        genre_path = plot_top_artist_genres()
        generated_files.append(genre_path)
        print(f"   ✅ Saved: {genre_path.name}")

        print("⏱️ 4. Analyzing track length preferences...")
        length_path = plot_track_length_distribution()
        generated_files.append(length_path)
        print(f"   ✅ Saved: {length_path.name}")

        print("📈 5. Mapping your discovery timeline...")
        timeline_path = plot_discovery_timeline()
        generated_files.append(timeline_path)
        print(f"   ✅ Saved: {timeline_path.name}")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()

    print(f"🎉 Generated {len(generated_files)} surprise visualizations!")
    print("📁 Check the 'data' folder to see your music personality revealed!")

    return generated_files


if __name__ == "__main__":
    generate_simple_surprise_visualizations()
