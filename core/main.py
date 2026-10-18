from pathlib import Path

from .fetch import fetch_recently_played, fetch_top_artists
from .utils import save_dataframe
from .visualize import plot_recently_played_heatmap, plot_top_artists_bar

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def run():
    # Fetch and save top artists
    df_artists = fetch_top_artists(limit=20, time_range="short_term")
    csv_path = save_dataframe(df_artists, DATA_DIR / "top_artists_short_term.csv")

    # Plot and save chart
    img_path = plot_top_artists_bar(df_artists, title="Top 10 Artists (short term)")

    print(f"Saved CSV -> {csv_path}")
    print(f"Saved chart -> {img_path}")

    # Recently played heatmap
    df_recent = fetch_recently_played(limit=50)
    rec_csv = save_dataframe(df_recent, DATA_DIR / "recently_played.csv")
    heatmap_path = plot_recently_played_heatmap(df_recent)
    print(f"Saved CSV -> {rec_csv}")
    print(f"Saved chart -> {heatmap_path}")


if __name__ == "__main__":
    run()
