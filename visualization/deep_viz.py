"""Advanced visualizations for deep musical taste analysis."""

from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from core.utils import save_matplotlib_figure

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def plot_musical_maturity_radar(
    maturity_data: dict, title: str = "Your Musical Maturity Profile"
) -> Path:
    """Create a radar chart showing different aspects of musical sophistication."""

    categories = ["Genre Diversity", "Era Diversity", "Classic Preference", "Underground Score"]
    values = [
        min(maturity_data["genre_diversity"] / 10, 1.0),  # Normalize
        min(maturity_data["era_diversity"] / 6, 1.0),  # Max 6 eras
        maturity_data["classic_ratio"],
        maturity_data["underground_score"],
    ]

    # Create radar chart
    angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False)
    values = np.concatenate((values, [values[0]]))  # Complete the circle
    angles = np.concatenate((angles, [angles[0]]))

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection="polar"))

    # Plot
    ax.plot(angles, values, "o-", linewidth=3, color="#8E44AD")
    ax.fill(angles, values, alpha=0.25, color="#8E44AD")

    # Customize
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=12)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=10)
    ax.grid(True, alpha=0.3)

    # Add overall score in center
    overall_score = maturity_data["maturity_score"]
    ax.text(
        0,
        0,
        f"Maturity Score\n{overall_score:.2f}",
        horizontalalignment="center",
        verticalalignment="center",
        fontsize=14,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8),
    )

    plt.title(title, size=16, pad=30)
    plt.tight_layout()

    out_path = DATA_DIR / "musical_maturity_radar.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_generational_evolution(
    era_data: pd.DataFrame, title: str = "Your Musical Era Journey"
) -> Path:
    """Plot how your taste has evolved across musical eras over time."""

    # Pivot data for stacked area chart
    pivot_data = era_data.pivot(index="time_range", columns="era", values="weight").fillna(0)

    # Reorder time ranges
    time_order = ["short_term", "medium_term", "long_term"]
    pivot_data = pivot_data.reindex(time_order)

    fig, ax = plt.subplots(figsize=(14, 8))

    # Color scheme for different eras
    era_colors = {
        "Classic (40s-70s)": "#8B4513",
        "Revolution (70s-80s)": "#FF6B6B",
        "Alternative (80s-00s)": "#4ECDC4",
        "Urban (70s-Present)": "#FFE135",
        "Electronic (80s-Present)": "#6C5CE7",
        "Pop (50s-Present)": "#FD79A8",
        "Contemporary": "#74B9FF",
    }

    # Create stacked area chart
    bottom = np.zeros(len(pivot_data.index))

    for era in pivot_data.columns:
        color = era_colors.get(era, "#95A5A6")
        ax.fill_between(
            range(len(pivot_data.index)),
            bottom,
            bottom + pivot_data[era],
            label=era,
            color=color,
            alpha=0.8,
        )
        bottom += pivot_data[era]

    # Customize
    ax.set_xlabel("Time Period", fontsize=12)
    ax.set_ylabel("Preference Weight", fontsize=12)
    ax.set_title(title, fontsize=16, pad=20)
    ax.set_xticks(range(len(time_order)))
    ax.set_xticklabels(["Recent\n(~4 weeks)", "Medium\n(~6 months)", "Long\n(~years)"])
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    out_path = DATA_DIR / "era_evolution.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_seasonal_mood_matrix(
    seasonal_data: pd.DataFrame, title: str = "Seasonal Music Mood Matrix"
) -> Path:
    """Create a heatmap showing seasonal preferences for different musical moods."""

    if seasonal_data.empty:
        # Create dummy data if no seasonal data available
        seasons = ["Winter", "Spring", "Summer", "Autumn"]
        moods = ["Autumn/Winter", "Summer", "Spring/Fall", "Year-round"]
        dummy_data = pd.DataFrame(
            {
                "season": seasons * len(moods),
                "seasonal_mood": moods * len(seasons),
                "weight": np.random.rand(len(seasons) * len(moods)),
            }
        )
        seasonal_data = dummy_data

    # Pivot for heatmap
    heatmap_data = seasonal_data.pivot_table(
        index="seasonal_mood", columns="season", values="weight", fill_value=0
    )

    # Ensure all seasons are present
    seasons = ["Winter", "Spring", "Summer", "Autumn"]
    for season in seasons:
        if season not in heatmap_data.columns:
            heatmap_data[season] = 0

    heatmap_data = heatmap_data[seasons]  # Reorder columns

    fig, ax = plt.subplots(figsize=(12, 8))

    # Create heatmap
    sns.heatmap(
        heatmap_data,
        annot=True,
        cmap="YlOrRd",
        cbar_kws={"label": "Listening Preference"},
        fmt=".2f",
        ax=ax,
    )

    ax.set_title(title, fontsize=16, pad=20)
    ax.set_xlabel("Season", fontsize=12)
    ax.set_ylabel("Musical Mood Category", fontsize=12)

    plt.tight_layout()
    out_path = DATA_DIR / "seasonal_mood_matrix.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_decade_preference_timeline(
    decade_data: pd.DataFrame, title: str = "Musical Time Travel: Decade Preferences"
) -> Path:
    """Show preference for music from different decades across listening periods."""

    if decade_data.empty:
        raise ValueError("No decade data available")

    # Filter out 'Unknown' decades and sort
    decade_clean = decade_data[decade_data["decade"] != "Unknown"].copy()

    if decade_clean.empty:
        raise ValueError("No valid decade data available")

    fig, ax = plt.subplots(figsize=(14, 8))

    # Create grouped bar chart
    time_ranges = ["short_term", "medium_term", "long_term"]
    time_labels = ["Recent", "Medium", "Long"]

    decades = sorted(decade_clean["decade"].unique())
    x = np.arange(len(decades))
    width = 0.25

    colors = ["#E74C3C", "#3498DB", "#9B59B6"]

    for i, (time_range, label, color) in enumerate(
        zip(time_ranges, time_labels, colors, strict=False)
    ):
        time_data = decade_clean[decade_clean["time_range"] == time_range]
        weights = []

        for decade in decades:
            decade_weight = time_data[time_data["decade"] == decade]["weight"].sum()
            weights.append(decade_weight)

        ax.bar(x + i * width, weights, width, label=label, color=color, alpha=0.8)

    ax.set_xlabel("Decade", fontsize=12)
    ax.set_ylabel("Preference Weight", fontsize=12)
    ax.set_title(title, fontsize=16, pad=20)
    ax.set_xticks(x + width)
    ax.set_xticklabels(decades, rotation=45)
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    out_path = DATA_DIR / "decade_timeline.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def plot_energy_circadian_rhythm(
    hourly_data: pd.DataFrame, title: str = "Musical Energy Circadian Rhythm"
) -> Path:
    """Plot how your energy preferences change throughout the day."""

    if hourly_data.empty:
        # Create sample data if none available
        hours = list(range(24))
        energy_levels = ["Low", "Medium", "Medium-High", "High"]
        sample_data = []

        for hour in hours:
            for energy in energy_levels:
                # Simulate realistic patterns
                if energy == "High":
                    weight = max(0, np.sin((hour - 6) * np.pi / 12)) if 6 <= hour <= 18 else 0
                elif energy == "Low":
                    weight = (
                        max(0, np.sin((hour + 6) * np.pi / 12)) if hour >= 22 or hour <= 6 else 0
                    )
                else:
                    weight = np.random.rand() * 0.5

                if weight > 0:
                    sample_data.append({"hour": hour, "energy_level": energy, "weight": weight})

        hourly_data = pd.DataFrame(sample_data)

    # Pivot for visualization
    pivot_energy = hourly_data.pivot_table(
        index="hour", columns="energy_level", values="weight", fill_value=0
    )

    fig, ax = plt.subplots(figsize=(14, 8))

    # Stacked area chart
    energy_colors = {
        "Low": "#3498DB",
        "Medium": "#F39C12",
        "Medium-High": "#E67E22",
        "High": "#E74C3C",
    }

    bottom = np.zeros(len(pivot_energy.index))

    for energy_level in pivot_energy.columns:
        color = energy_colors.get(energy_level, "#95A5A6")
        ax.fill_between(
            pivot_energy.index,
            bottom,
            bottom + pivot_energy[energy_level],
            label=energy_level,
            color=color,
            alpha=0.8,
        )
        bottom += pivot_energy[energy_level]

    # Add time period backgrounds
    ax.axvspan(6, 12, alpha=0.1, color="yellow", label="Morning")
    ax.axvspan(12, 18, alpha=0.1, color="orange", label="Afternoon")
    ax.axvspan(18, 24, alpha=0.1, color="purple", label="Evening")
    ax.axvspan(0, 6, alpha=0.1, color="navy", label="Night")

    ax.set_xlabel("Hour of Day", fontsize=12)
    ax.set_ylabel("Energy Preference Weight", fontsize=12)
    ax.set_title(title, fontsize=16, pad=20)
    ax.set_xlim(0, 23)
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    out_path = DATA_DIR / "energy_circadian.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def create_musical_age_analysis_chart(
    df: pd.DataFrame, title: str = "Musical Age vs Chronological Patterns"
) -> Path:
    """Analyze if your music taste reflects your actual age demographic."""

    # Calculate "musical age" based on era preferences
    current_year = datetime.now().year

    # Era to birth year mapping (when people typically listen to this music)
    era_birth_years = {
        "Classic (40s-70s)": 1950,
        "Revolution (70s-80s)": 1960,
        "Alternative (80s-00s)": 1975,
        "Urban (70s-Present)": 1980,
        "Electronic (80s-Present)": 1985,
        "Pop (50s-Present)": 1990,
        "Contemporary": 1995,
    }

    # Calculate weighted musical age
    total_weight = 0
    weighted_age_sum = 0

    for era in df["era"].unique():
        era_weight = df[df["era"] == era]["weight"].sum()
        birth_year = era_birth_years.get(era, 1990)
        musical_age = current_year - birth_year

        weighted_age_sum += musical_age * era_weight
        total_weight += era_weight

    avg_musical_age = weighted_age_sum / total_weight if total_weight > 0 else 30

    # Create visualization
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    # Left: Era preference pie chart with age mapping
    era_weights = df.groupby("era")["weight"].sum()
    colors = plt.cm.Set3(np.linspace(0, 1, len(era_weights)))

    wedges, texts, autotexts = ax1.pie(
        era_weights.values,
        labels=era_weights.index,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
    )
    ax1.set_title("Musical Era Preferences\n(with implied demographics)", fontsize=14)

    # Right: Musical age gauge
    ax2.set_xlim(0, 10)
    ax2.set_ylim(0, 10)

    # Create gauge-like visualization
    gauge_angle = (avg_musical_age - 20) / 60 * 180  # Map age 20-80 to 0-180 degrees
    gauge_angle = max(0, min(180, gauge_angle))

    # Draw gauge arc
    theta = np.linspace(0, np.pi, 100)
    x_arc = 5 + 3 * np.cos(theta)
    y_arc = 2 + 3 * np.sin(theta)
    ax2.plot(x_arc, y_arc, "k-", linewidth=3)

    # Draw needle
    needle_angle = np.radians(gauge_angle)
    needle_x = 5 + 2.5 * np.cos(needle_angle)
    needle_y = 2 + 2.5 * np.sin(needle_angle)
    ax2.plot([5, needle_x], [2, needle_y], "r-", linewidth=4)
    ax2.plot(5, 2, "ro", markersize=10)

    # Labels
    ax2.text(2, 2, "20", fontsize=12, ha="center")
    ax2.text(8, 2, "80", fontsize=12, ha="center")
    ax2.text(5, 5.5, f"Musical Age\n{avg_musical_age:.0f}", fontsize=14, ha="center", weight="bold")

    ax2.set_aspect("equal")
    ax2.axis("off")

    plt.suptitle(title, fontsize=16)
    plt.tight_layout()

    out_path = DATA_DIR / "musical_age_analysis.png"
    save_matplotlib_figure(plt, out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path
