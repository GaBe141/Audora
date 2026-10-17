from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from core.utils import save_matplotlib_figure

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def plot_audio_dna_radar(df: pd.DataFrame, title: str = "Your Audio DNA") -> Path:
    """Create a radar chart showing your average audio characteristics."""
    if df.empty:
        raise ValueError("DataFrame is empty")

    # Audio features for radar chart
    features = [
        "danceability",
        "energy",
        "valence",
        "acousticness",
        "instrumentalness",
        "speechiness",
    ]

    # Calculate means for each feature
    means = df[features].mean()

    # Set up radar chart
    angles = np.linspace(0, 2 * np.pi, len(features), endpoint=False)
    angles = np.concatenate((angles, [angles[0]]))  # Complete the circle
    values = np.concatenate((means.values, [means.values[0]]))

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(projection="polar"))

    # Plot the radar chart
    ax.plot(angles, values, "o-", linewidth=2, color="#1DB954")
    ax.fill(angles, values, alpha=0.25, color="#1DB954")

    # Customize the chart
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels([f.title() for f in features])
    ax.set_ylim(0, 1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], size=8)
    ax.grid(True)

    plt.title(title, size=16, pad=20)

    out_path = DATA_DIR / "audio_dna_radar.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_mood_evolution(df: pd.DataFrame, title: str = "Mood Evolution Over Time") -> Path:
    """Plot valence (happiness) and energy over time using recently played data."""
    if df.empty or "played_at" not in df.columns:
        raise ValueError("DataFrame must have 'played_at' column")

    # Sort by time
    df_sorted = df.sort_values("played_at").copy()
    df_sorted["hour"] = df_sorted["played_at"].dt.hour

    # Group by hour and calculate means
    hourly_mood = df_sorted.groupby("hour").agg({"valence": "mean", "energy": "mean"}).reset_index()

    fig, ax = plt.subplots(figsize=(12, 6))

    # Plot valence and energy
    ax.plot(
        hourly_mood["hour"],
        hourly_mood["valence"],
        marker="o",
        linewidth=2,
        label="Happiness (Valence)",
        color="#FFD700",
    )
    ax.plot(
        hourly_mood["hour"],
        hourly_mood["energy"],
        marker="s",
        linewidth=2,
        label="Energy",
        color="#FF6B6B",
    )

    ax.set_xlabel("Hour of Day")
    ax.set_ylabel("Audio Feature Value (0-1)")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_xlim(0, 23)
    ax.set_ylim(0, 1)

    # Add time period annotations
    ax.axvspan(6, 12, alpha=0.1, color="yellow", label="Morning")
    ax.axvspan(12, 18, alpha=0.1, color="orange", label="Afternoon")
    ax.axvspan(18, 24, alpha=0.1, color="purple", label="Evening")
    ax.axvspan(0, 6, alpha=0.1, color="navy", label="Night")

    plt.tight_layout()
    out_path = DATA_DIR / "mood_evolution.png"
    save_matplotlib_figure(plt, out_path, dpi=150)
    plt.close()
    return out_path


def plot_genre_evolution(df: pd.DataFrame, title: str = "Genre Evolution Across Time") -> Path:
    """Create a stacked area chart showing genre popularity over time ranges."""
    if df.empty:
        raise ValueError("DataFrame is empty")

    # Count genres by time range
    genre_counts = df.groupby(["time_range", "genre"]).size().reset_index(name="count")

    # Get top genres overall
    top_genres = df["genre"].value_counts().head(8).index
    genre_counts = genre_counts[genre_counts["genre"].isin(top_genres)]

    # Pivot for plotting
    pivot_data = genre_counts.pivot(index="time_range", columns="genre", values="count").fillna(0)

    # Reorder time ranges
    time_order = ["short_term", "medium_term", "long_term"]
    pivot_data = pivot_data.reindex(time_order)

    fig, ax = plt.subplots(figsize=(12, 8))

    # Create stacked area chart
    colors = plt.cm.Set3(np.linspace(0, 1, len(pivot_data.columns)))
    ax.stackplot(
        range(len(pivot_data.index)),
        *[pivot_data[col] for col in pivot_data.columns],
        labels=pivot_data.columns,
        colors=colors,
        alpha=0.8,
    )

    ax.set_xlabel("Time Range")
    ax.set_ylabel("Genre Occurrences")
    ax.set_title(title)
    ax.set_xticks(range(len(time_order)))
    ax.set_xticklabels(["Recent\n(~4 weeks)", "Medium\n(~6 months)", "Long\n(~years)"])
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")

    plt.tight_layout()
    out_path = DATA_DIR / "genre_evolution.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_playlist_characteristics(
    df: pd.DataFrame, title: str = "Playlist Audio Landscapes"
) -> Path:
    """Create a scatter plot matrix of playlist audio characteristics."""
    if df.empty or len(df) < 3:
        raise ValueError("Need at least 3 playlists for meaningful visualization")

    # Select key features for comparison

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.ravel()

    # Create scatter plots for different feature combinations
    combinations = [
        ("danceability", "energy"),
        ("valence", "energy"),
        ("acousticness", "danceability"),
        ("valence", "acousticness"),
    ]

    for i, (x_feat, y_feat) in enumerate(combinations):
        ax = axes[i]
        scatter = ax.scatter(
            df[x_feat],
            df[y_feat],
            c=df["track_count"],
            cmap="viridis",
            s=100,
            alpha=0.7,
            edgecolors="black",
        )

        # Add playlist names as annotations
        for idx, row in df.iterrows():
            if len(row["playlist_name"]) < 15:  # Only annotate shorter names
                ax.annotate(
                    row["playlist_name"],
                    (row[x_feat], row[y_feat]),
                    xytext=(5, 5),
                    textcoords="offset points",
                    fontsize=8,
                    alpha=0.8,
                )

        ax.set_xlabel(x_feat.title())
        ax.set_ylabel(y_feat.title())
        ax.grid(True, alpha=0.3)

        # Add colorbar for track count
        if i == 1:  # Add colorbar to one subplot
            plt.colorbar(scatter, ax=ax, label="Track Count")

    plt.suptitle(title, size=16)
    plt.tight_layout()

    out_path = DATA_DIR / "playlist_landscapes.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_tempo_energy_dance_3d(df: pd.DataFrame, title: str = "Your Music in 3D Space") -> Path:
    """Create a 3D scatter plot of tempo vs energy vs danceability."""
    if df.empty:
        raise ValueError("DataFrame is empty")

    fig = plt.figure(figsize=(12, 9))
    ax = fig.add_subplot(111, projection="3d")

    # Create 3D scatter plot
    scatter = ax.scatter(
        df["tempo"],
        df["energy"],
        df["danceability"],
        c=df["valence"],
        cmap="RdYlBu",
        s=50,
        alpha=0.7,
    )

    ax.set_xlabel("Tempo (BPM)")
    ax.set_ylabel("Energy")
    ax.set_zlabel("Danceability")
    ax.set_title(title)

    # Add colorbar
    cbar = plt.colorbar(scatter, ax=ax, shrink=0.5, aspect=5)
    cbar.set_label("Valence (Happiness)")

    plt.tight_layout()
    out_path = DATA_DIR / "music_3d_space.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path
