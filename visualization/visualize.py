from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from core.utils import save_matplotlib_figure

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def plot_top_artists_bar(df: pd.DataFrame, title: str = "Top Artists (short term)") -> Path:
    """Save a horizontal bar chart of top artists to data/top_artists.png.

    Expects df with columns: [rank, name, popularity].
    """
    if df.empty:
        raise ValueError("DataFrame is empty; fetch data first.")

    out_path = DATA_DIR / "top_artists.png"
    plt.figure(figsize=(8, 6))
    sns.barplot(
        data=df.sort_values("rank").head(10),
        y="name",
        x="popularity",
        palette="viridis",
    )
    plt.xlabel("Popularity")
    plt.ylabel("Artist")
    plt.title(title)
    plt.tight_layout()
    save_matplotlib_figure(plt, out_path, dpi=150)
    plt.close()
    return out_path


def plot_recently_played_heatmap(
    df: pd.DataFrame, title: str = "Listening heatmap (last 50)"
) -> Path:
    """Plot a heatmap of play counts by day of week vs hour.

    Expects df with column 'played_at' as datetime.
    Saves to data/recently_played_heatmap.png and returns the path.
    """
    if df.empty:
        raise ValueError("DataFrame is empty; fetch data first.")

    if df["played_at"].dtype == "O":
        # If not yet converted to datetime, try now
        df = df.copy()
        df["played_at"] = pd.to_datetime(df["played_at"], errors="coerce")

    # Derive hour and day order
    tmp = df.dropna(subset=["played_at"]).copy()
    tmp["hour"] = tmp["played_at"].dt.hour
    tmp["dow"] = tmp["played_at"].dt.day_name()
    # Order days starting Monday
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    tmp["dow"] = pd.Categorical(tmp["dow"], categories=day_order, ordered=True)

    # Pivot to counts
    pivot = tmp.pivot_table(
        index="dow", columns="hour", values="track_id", aggfunc="count", fill_value=0
    )

    out_path = DATA_DIR / "recently_played_heatmap.png"
    plt.figure(figsize=(10, 4))
    sns.heatmap(pivot, cmap="YlGnBu", cbar=True)
    plt.title(title)
    plt.xlabel("Hour of day")
    plt.ylabel("Day of week")
    plt.tight_layout()
    save_matplotlib_figure(plt, out_path, dpi=150)
    plt.close()
    return out_path
