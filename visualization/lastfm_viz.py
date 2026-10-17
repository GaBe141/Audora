"""Visualizations comparing your personal taste with global Last.fm trends."""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from core.utils import save_matplotlib_figure

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def plot_personal_vs_global_artists(
    spotify_df: pd.DataFrame, lastfm_df: pd.DataFrame, title: str = "Your Taste vs Global Trends"
) -> Path:
    """Compare your top artists with global Last.fm charts."""

    if spotify_df.empty or lastfm_df.empty:
        raise ValueError("Need both Spotify and Last.fm data")

    # Find overlapping artists
    spotify_artists = set(spotify_df["name"].str.lower())
    lastfm_artists = set(lastfm_df["name"].str.lower())
    overlap = spotify_artists.intersection(lastfm_artists)

    # Calculate mainstream vs underground score
    mainstream_count = len(overlap)
    total_your_artists = len(spotify_artists)
    mainstream_percentage = (mainstream_count / total_your_artists) * 100

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

    # 1. Venn diagram-style comparison
    ax1.pie(
        [mainstream_count, total_your_artists - mainstream_count],
        labels=[
            f"Mainstream\n({mainstream_count})",
            f"Underground\n({total_your_artists - mainstream_count})",
        ],
        colors=["#FF6B6B", "#4ECDC4"],
        autopct="%1.1f%%",
        startangle=90,
    )
    ax1.set_title(f"Your Mainstream vs Underground Ratio\n{mainstream_percentage:.1f}% Mainstream")

    # 2. Top 10 comparison
    your_top_10 = spotify_df.head(10)["name"].tolist()
    global_top_10 = lastfm_df.head(10)["name"].tolist()

    # Create comparison chart
    y_pos = np.arange(10)
    ax2.barh(y_pos, [10 - i for i in range(10)], color="#3498DB", alpha=0.7, label="Your Top 10")
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(
        [
            f"{i+1}. {name[:20]}..." if len(name) > 20 else f"{i+1}. {name}"
            for i, name in enumerate(your_top_10)
        ]
    )
    ax2.set_xlabel("Your Ranking (inverted for display)")
    ax2.set_title("Your Top 10 Artists")
    ax2.grid(True, alpha=0.3)

    # 3. Global top 10
    ax3.barh(y_pos, [10 - i for i in range(10)], color="#E74C3C", alpha=0.7, label="Global Top 10")
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(
        [
            f"{i+1}. {name[:20]}..." if len(name) > 20 else f"{i+1}. {name}"
            for i, name in enumerate(global_top_10)
        ]
    )
    ax3.set_xlabel("Global Ranking (inverted for display)")
    ax3.set_title("Global Top 10 Artists (Last.fm)")
    ax3.grid(True, alpha=0.3)

    # 4. Overlap analysis
    overlap_artists = list(overlap)[:10]  # Top 10 overlapping
    if overlap_artists:
        overlap_counts = []
        for artist in overlap_artists:
            # Get ranks from both datasets
            spotify_rank = (
                spotify_df[spotify_df["name"].str.lower() == artist].index[0] + 1
                if len(spotify_df[spotify_df["name"].str.lower() == artist]) > 0
                else 999
            )
            lastfm_rank = (
                lastfm_df[lastfm_df["name"].str.lower() == artist].index[0] + 1
                if len(lastfm_df[lastfm_df["name"].str.lower() == artist]) > 0
                else 999
            )
            overlap_counts.append((artist.title(), spotify_rank, lastfm_rank))

        overlap_df = pd.DataFrame(overlap_counts, columns=["Artist", "Your_Rank", "Global_Rank"])

        ax4.scatter(
            overlap_df["Your_Rank"], overlap_df["Global_Rank"], s=100, alpha=0.7, color="purple"
        )
        for i, row in overlap_df.iterrows():
            ax4.annotate(
                row["Artist"][:15],
                (row["Your_Rank"], row["Global_Rank"]),
                xytext=(5, 5),
                textcoords="offset points",
                fontsize=8,
            )

        ax4.set_xlabel("Your Ranking")
        ax4.set_ylabel("Global Ranking")
        ax4.set_title("Shared Artists: Your Rank vs Global Rank")
        ax4.grid(True, alpha=0.3)

        # Add diagonal line (perfect correlation)
        max_rank = max(overlap_df["Your_Rank"].max(), overlap_df["Global_Rank"].max())
        ax4.plot(
            [1, max_rank], [1, max_rank], "--", color="gray", alpha=0.5, label="Perfect correlation"
        )
        ax4.legend()
    else:
        ax4.text(
            0.5,
            0.5,
            "No overlapping artists\nin top rankings!",
            ha="center",
            va="center",
            transform=ax4.transAxes,
            fontsize=14,
        )
        ax4.set_title("Shared Artists Analysis")

    plt.suptitle(title, size=16, y=0.98)
    plt.tight_layout()

    out_path = DATA_DIR / "personal_vs_global_trends.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_genre_popularity_matrix(
    genre_trends: dict[str, pd.DataFrame], title: str = "Global Genre Popularity Matrix"
) -> Path:
    """Create a matrix showing top artists across different genres."""

    if not genre_trends:
        raise ValueError("No genre trend data available")

    # Prepare data for heatmap
    genres = [
        key.replace("genre_", "").replace("_", " ").title()
        for key in genre_trends
        if key.startswith("genre_")
    ]

    if not genres:
        raise ValueError("No genre data found")

    # Get top 10 artists per genre
    matrix_data = []
    all_artists = set()

    for genre in genres:
        genre_key = f"genre_{genre.lower().replace(' ', '_')}"
        if genre_key in genre_trends:
            df = genre_trends[genre_key]
            top_artists = df.head(10)["name"].tolist()
            all_artists.update(top_artists)
            matrix_data.append((genre, top_artists))

    # Create artist popularity matrix
    list(all_artists)[:20]  # Limit for visualization

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))

    # 1. Genre popularity bars
    genre_sizes = []
    for genre in genres:
        genre_key = f"genre_{genre.lower().replace(' ', '_')}"
        if genre_key in genre_trends:
            genre_sizes.append(len(genre_trends[genre_key]))
        else:
            genre_sizes.append(0)

    bars = ax1.barh(genres, genre_sizes, color=plt.cm.Set3(np.linspace(0, 1, len(genres))))
    ax1.set_xlabel("Number of Top Artists")
    ax1.set_title("Artists per Genre (Last.fm)")
    ax1.grid(True, alpha=0.3)

    # Add value labels on bars
    for bar, size in zip(bars, genre_sizes, strict=False):
        ax1.text(
            bar.get_width() + 0.5,
            bar.get_y() + bar.get_height() / 2,
            str(size),
            va="center",
            fontsize=10,
        )

    # 2. Cross-genre artist appearance matrix
    if len(genres) > 1:
        # Create matrix showing artist overlap between genres
        overlap_matrix = np.zeros((len(genres), len(genres)))

        for i, genre1 in enumerate(genres):
            genre1_key = f"genre_{genre1.lower().replace(' ', '_')}"
            if genre1_key not in genre_trends:
                continue

            artists1 = set(genre_trends[genre1_key]["name"].str.lower())

            for j, genre2 in enumerate(genres):
                genre2_key = f"genre_{genre2.lower().replace(' ', '_')}"
                if genre2_key not in genre_trends:
                    continue

                artists2 = set(genre_trends[genre2_key]["name"].str.lower())
                overlap = len(artists1.intersection(artists2))
                overlap_matrix[i, j] = overlap

        # Plot heatmap
        im = ax2.imshow(overlap_matrix, cmap="YlOrRd", aspect="auto")
        ax2.set_xticks(range(len(genres)))
        ax2.set_yticks(range(len(genres)))
        ax2.set_xticklabels(genres, rotation=45, ha="right")
        ax2.set_yticklabels(genres)
        ax2.set_title("Cross-Genre Artist Overlap")

        # Add text annotations
        for i in range(len(genres)):
            for j in range(len(genres)):
                ax2.text(
                    j,
                    i,
                    int(overlap_matrix[i, j]),
                    ha="center",
                    va="center",
                    color="black",
                    fontsize=10,
                )

        # Add colorbar
        plt.colorbar(im, ax=ax2, label="Number of Shared Artists")

    plt.suptitle(title, size=16)
    plt.tight_layout()

    out_path = DATA_DIR / "global_genre_matrix.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_listening_influence_analysis(
    spotify_enriched: pd.DataFrame, title: str = "Your Artists: Local vs Global Influence"
) -> Path:
    """Analyze the global influence of your favorite artists."""

    if spotify_enriched.empty or "lastfm_listeners" not in spotify_enriched.columns:
        raise ValueError("Need Spotify data enriched with Last.fm stats")

    # Clean data
    df_clean = spotify_enriched.dropna(subset=["lastfm_listeners", "popularity"])
    df_clean = df_clean[df_clean["lastfm_listeners"] > 0]

    if df_clean.empty:
        raise ValueError("No valid Last.fm data found")

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

    # 1. Spotify Popularity vs Last.fm Global Listeners
    scatter = ax1.scatter(
        df_clean["popularity"],
        df_clean["lastfm_listeners"],
        c=df_clean["rank"],
        cmap="viridis",
        s=100,
        alpha=0.7,
    )
    ax1.set_xlabel("Spotify Popularity")
    ax1.set_ylabel("Last.fm Global Listeners")
    ax1.set_title("Spotify vs Last.fm Popularity")
    ax1.grid(True, alpha=0.3)

    # Add trend line
    if len(df_clean) > 5:
        z = np.polyfit(df_clean["popularity"], df_clean["lastfm_listeners"], 1)
        p = np.poly1d(z)
        ax1.plot(
            df_clean["popularity"],
            p(df_clean["popularity"]),
            "--",
            color="red",
            alpha=0.8,
            label="Trend",
        )
        ax1.legend()

    plt.colorbar(scatter, ax=ax1, label="Your Personal Rank")

    # 2. Global Reach Categories
    # Categorize artists by global reach
    listeners_median = df_clean["lastfm_listeners"].median()
    popularity_median = df_clean["popularity"].median()

    categories = []
    for _, row in df_clean.iterrows():
        if row["lastfm_listeners"] > listeners_median and row["popularity"] > popularity_median:
            categories.append("Global Superstars")
        elif row["lastfm_listeners"] > listeners_median and row["popularity"] <= popularity_median:
            categories.append("Cult Classics")
        elif row["lastfm_listeners"] <= listeners_median and row["popularity"] > popularity_median:
            categories.append("Rising Stars")
        else:
            categories.append("Hidden Gems")

    df_clean["category"] = categories
    category_counts = df_clean["category"].value_counts()

    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"]
    wedges, texts, autotexts = ax2.pie(
        category_counts.values,
        labels=category_counts.index,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
    )
    ax2.set_title("Your Artist Categories by Global Reach")

    # 3. Top Global vs Your Ranking
    top_global = df_clean.nlargest(10, "lastfm_listeners")
    y_pos = np.arange(len(top_global))

    ax3.barh(y_pos, top_global["rank"], color="#3498DB", alpha=0.7, label="Your Rank")
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(
        [f"{name[:15]}..." if len(name) > 15 else name for name in top_global["name"]]
    )
    ax3.set_xlabel("Your Personal Ranking")
    ax3.set_title("Most Globally Popular Artists in Your Top List")
    ax3.grid(True, alpha=0.3)
    ax3.invert_xaxis()  # Lower rank numbers = higher preference

    # 4. Influence Score vs Personal Preference
    # Create influence score combining listeners and playcount
    df_clean["influence_score"] = (
        (df_clean["lastfm_listeners"] / df_clean["lastfm_listeners"].max()) * 0.6
        + (df_clean["lastfm_playcount"] / df_clean["lastfm_playcount"].max()) * 0.4
    ) * 100

    scatter2 = ax4.scatter(
        df_clean["rank"],
        df_clean["influence_score"],
        c=df_clean["popularity"],
        cmap="plasma",
        s=100,
        alpha=0.7,
    )
    ax4.set_xlabel("Your Personal Rank (1 = most preferred)")
    ax4.set_ylabel("Global Influence Score")
    ax4.set_title("Your Preference vs Artist Global Influence")
    ax4.grid(True, alpha=0.3)
    ax4.invert_xaxis()

    plt.colorbar(scatter2, ax=ax4, label="Spotify Popularity")

    plt.suptitle(title, size=16, y=0.98)
    plt.tight_layout()

    out_path = DATA_DIR / "listening_influence_analysis.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path
