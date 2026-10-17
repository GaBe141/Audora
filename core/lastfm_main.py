"""Main script to integrate Last.fm data with your Spotify insights."""

from pathlib import Path

from .fetch import fetch_top_artists
from .lastfm_integration import enrich_spotify_artists_with_lastfm, fetch_global_trends
from .lastfm_viz import (
    plot_genre_popularity_matrix,
    plot_listening_influence_analysis,
    plot_personal_vs_global_artists,
)
from .utils import save_dataframe

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def run_lastfm_integration():
    """Run complete Last.fm integration analysis."""
    print("🌍 LAST.FM INTEGRATION ANALYSIS")
    print("=" * 50)
    print("This will compare your personal taste with global music trends")
    print()

    # Step 1: Get your Spotify data
    print("📱 1. Loading your Spotify data...")
    spotify_artists = fetch_top_artists(limit=50, time_range="medium_term")
    if spotify_artists.empty:
        print("❌ No Spotify artist data found. Run the main script first.")
        return

    print(f"   ✅ Loaded {len(spotify_artists)} of your top artists")

    # Step 2: Fetch global trends
    print()
    print("🌍 2. Fetching global trends from Last.fm...")
    global_trends = fetch_global_trends()

    if not global_trends:
        print("❌ Could not fetch Last.fm data. Check your API key in .env")
        return

    print(f"   ✅ Fetched {len(global_trends)} trend categories")

    # Step 3: Enrich your data with global stats
    print()
    print("🔗 3. Enriching your artists with global data...")
    spotify_enriched = enrich_spotify_artists_with_lastfm(
        spotify_artists.head(20)
    )  # Limit to avoid rate limits

    # Step 4: Generate visualizations
    print()
    print("🎨 4. Creating comparative visualizations...")
    generated_files = []

    try:
        # Personal vs Global comparison
        if "global_top_artists" in global_trends:
            print("   📊 Personal vs Global trends...")
            comparison_path = plot_personal_vs_global_artists(
                spotify_artists, global_trends["global_top_artists"]
            )
            generated_files.append(comparison_path)
            print(f"      ✅ {comparison_path.name}")

        # Genre popularity matrix
        genre_data = {k: v for k, v in global_trends.items() if k.startswith("genre_")}
        if genre_data:
            print("   🎭 Genre popularity analysis...")
            genre_path = plot_genre_popularity_matrix(genre_data)
            generated_files.append(genre_path)
            print(f"      ✅ {genre_path.name}")

        # Influence analysis
        if not spotify_enriched.empty and "lastfm_listeners" in spotify_enriched.columns:
            print("   🌟 Artist influence analysis...")
            influence_path = plot_listening_influence_analysis(spotify_enriched)
            generated_files.append(influence_path)
            print(f"      ✅ {influence_path.name}")

    except Exception as e:
        print(f"   ❌ Visualization error: {e}")
        import traceback

        traceback.print_exc()

    # Step 5: Analysis summary
    print()
    print("📊 ANALYSIS RESULTS:")
    print("=" * 30)

    if "global_top_artists" in global_trends:
        # Calculate mainstream vs underground
        your_artists = set(spotify_artists["name"].str.lower())
        global_artists = set(global_trends["global_top_artists"]["name"].str.lower())
        overlap = your_artists.intersection(global_artists)

        mainstream_percentage = (len(overlap) / len(your_artists)) * 100
        print(f"🎯 Mainstream Score: {mainstream_percentage:.1f}%")
        print(f"   • {len(overlap)} of your top artists are globally popular")
        print(f"   • {len(your_artists) - len(overlap)} are more underground/niche")

        if overlap:
            print(f"   • Shared favorites: {', '.join(list(overlap)[:5])}")

    if not spotify_enriched.empty and "lastfm_listeners" in spotify_enriched.columns:
        # Global influence stats
        valid_data = spotify_enriched.dropna(subset=["lastfm_listeners"])
        if not valid_data.empty:
            avg_listeners = valid_data["lastfm_listeners"].mean()
            max_listeners = valid_data["lastfm_listeners"].max()
            most_popular_artist = valid_data.loc[valid_data["lastfm_listeners"].idxmax(), "name"]

            print("🌍 Global Reach Analysis:")
            print(f"   • Average global listeners: {avg_listeners:,.0f}")
            print(
                f"   • Most globally popular: {most_popular_artist} ({max_listeners:,.0f} listeners)"
            )

    # Genre breakdown
    if genre_data:
        print("🎭 Genre Analysis:")
        for genre_key, genre_df in list(genre_data.items())[:5]:
            genre_name = genre_key.replace("genre_", "").replace("_", " ").title()
            print(f"   • {genre_name}: {len(genre_df)} top artists tracked")

    # Save data files
    print()
    print("📁 Data Files Saved:")

    # Save global trends
    if "global_top_artists" in global_trends:
        global_csv = save_dataframe(
            global_trends["global_top_artists"], DATA_DIR / "lastfm_global_artists.csv"
        )
        print(f"   • {global_csv.name}")

    if "global_top_tracks" in global_trends:
        tracks_csv = save_dataframe(
            global_trends["global_top_tracks"], DATA_DIR / "lastfm_global_tracks.csv"
        )
        print(f"   • {tracks_csv.name}")

    # Save enriched data
    if not spotify_enriched.empty:
        enriched_csv = save_dataframe(spotify_enriched, DATA_DIR / "spotify_lastfm_enriched.csv")
        print(f"   • {enriched_csv.name}")

    print()
    print(f"🎉 Analysis complete! Generated {len(generated_files)} visualizations")
    print("🔍 Check the visualizations to see how your taste compares globally!")

    return generated_files


if __name__ == "__main__":
    run_lastfm_integration()
