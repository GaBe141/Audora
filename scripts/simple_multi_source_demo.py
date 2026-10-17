"""Simple multi-source demo that works with current API integrations."""

import sys
from pathlib import Path

import pandas as pd

# Add core to path for utilities
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.audiodb_integration import get_audiodb_client
from src.fetch import fetch_top_artists, fetch_top_tracks
from src.musicbrainz_integration import get_musicbrainz_client

from core.utils import save_dataframe


def simple_multi_source_demo():
    """Run a simple demo of multi-source integration."""
    print("🎵 Simple Multi-Source Integration Demo")
    print("=" * 50)

    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    # 1. Get Spotify data
    print("\n1️⃣ Collecting Spotify data...")
    try:
        top_artists = fetch_top_artists(limit=10, time_range="medium_term")
        top_tracks = fetch_top_tracks(limit=10, time_range="medium_term")

        print(f"✅ Got {len(top_artists)} top artists and {len(top_tracks)} top tracks")

        # Save Spotify data
        save_dataframe(top_artists, data_dir / "simple_top_artists.csv")
        save_dataframe(top_tracks, data_dir / "simple_top_tracks.csv")

    except Exception as e:
        print(f"❌ Spotify error: {e}")
        return

    # 2. Enrich with MusicBrainz
    print("\n2️⃣ Enriching with MusicBrainz data...")
    try:
        mb_client = get_musicbrainz_client()
        enriched_artists = []

        for _, artist_row in top_artists.head(5).iterrows():  # Just top 5 for demo
            artist_name = artist_row["name"]
            print(f"   Searching: {artist_name}")

            mb_artist = mb_client.search_artist(artist_name)
            if mb_artist:
                enriched_artists.append(
                    {
                        "spotify_name": artist_name,
                        "spotify_id": artist_row["id"],
                        "spotify_popularity": artist_row["popularity"],
                        "mb_name": mb_artist["name"],
                        "mb_id": mb_artist["id"],
                        "mb_country": mb_artist.get("country"),
                        "mb_type": mb_artist.get("type"),
                        "mb_disambiguation": mb_artist.get("disambiguation"),
                    }
                )
            else:
                enriched_artists.append(
                    {
                        "spotify_name": artist_name,
                        "spotify_id": artist_row["id"],
                        "spotify_popularity": artist_row["popularity"],
                        "mb_name": None,
                        "mb_id": None,
                        "mb_country": None,
                        "mb_type": None,
                        "mb_disambiguation": None,
                    }
                )

        enriched_df = pd.DataFrame(enriched_artists)
        save_dataframe(enriched_df, data_dir / "musicbrainz_enriched.csv")

        print(f"✅ Enriched {len(enriched_df)} artists with MusicBrainz data")

    except Exception as e:
        print(f"❌ MusicBrainz error: {e}")
        enriched_df = pd.DataFrame()

    # 3. Enrich with AudioDB
    print("\n3️⃣ Enriching with AudioDB data...")
    try:
        audiodb_client = get_audiodb_client()
        audiodb_enriched = []

        for _, artist_row in top_artists.head(3).iterrows():  # Just top 3 for demo
            artist_name = artist_row["name"]
            print(f"   Getting AudioDB data: {artist_name}")

            audiodb_details = audiodb_client.get_artist_details(artist_name)
            if audiodb_details and audiodb_details["name"]:
                audiodb_enriched.append(
                    {
                        "spotify_name": artist_name,
                        "audiodb_name": audiodb_details["name"],
                        "audiodb_country": audiodb_details["country"],
                        "audiodb_genre": audiodb_details["genre"],
                        "audiodb_formed_year": audiodb_details["formed_year"],
                        "audiodb_biography": (
                            audiodb_details["biography"][:200] + "..."
                            if audiodb_details["biography"]
                            else None
                        ),
                    }
                )
            else:
                audiodb_enriched.append(
                    {
                        "spotify_name": artist_name,
                        "audiodb_name": None,
                        "audiodb_country": None,
                        "audiodb_genre": None,
                        "audiodb_formed_year": None,
                        "audiodb_biography": None,
                    }
                )

        audiodb_df = pd.DataFrame(audiodb_enriched)
        save_dataframe(audiodb_df, data_dir / "audiodb_enriched.csv")

        print(f"✅ Enriched {len(audiodb_df)} artists with AudioDB data")

    except Exception as e:
        print(f"❌ AudioDB error: {e}")
        audiodb_df = pd.DataFrame()

    # 4. Generate summary insights
    print("\n4️⃣ Generating insights...")

    insights = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "spotify_data": {
            "total_artists": len(top_artists),
            "total_tracks": len(top_tracks),
            "top_artist": top_artists.iloc[0]["name"] if len(top_artists) > 0 else None,
            "top_track": top_tracks.iloc[0]["name"] if len(top_tracks) > 0 else None,
        },
    }

    # MusicBrainz insights
    if not enriched_df.empty:
        countries = enriched_df["mb_country"].dropna()
        insights["musicbrainz_data"] = {
            "artists_found": len(enriched_df[enriched_df["mb_name"].notna()]),
            "unique_countries": len(countries.unique()) if len(countries) > 0 else 0,
            "top_country": countries.mode().iloc[0] if len(countries) > 0 else None,
        }

    # AudioDB insights
    if not audiodb_df.empty:
        genres = audiodb_df["audiodb_genre"].dropna()
        formed_years = audiodb_df["audiodb_formed_year"].dropna()
        insights["audiodb_data"] = {
            "artists_found": len(audiodb_df[audiodb_df["audiodb_name"].notna()]),
            "unique_genres": len(genres.unique()) if len(genres) > 0 else 0,
            "average_formation_year": (
                int(pd.to_numeric(formed_years, errors="coerce").mean())
                if len(formed_years) > 0
                else None
            ),
        }

    # Save insights using centralized utility
    from core.utils import write_json

    write_json(str(data_dir / "simple_insights.json"), insights)

    # Print summary
    print("\n" + "=" * 50)
    print("📊 SIMPLE MULTI-SOURCE ANALYSIS COMPLETE")
    print("=" * 50)

    print(
        f"🎵 Spotify: {insights['spotify_data']['total_artists']} artists, {insights['spotify_data']['total_tracks']} tracks"
    )
    if insights["spotify_data"]["top_artist"]:
        print(f"   Top Artist: {insights['spotify_data']['top_artist']}")

    if "musicbrainz_data" in insights:
        mb_data = insights["musicbrainz_data"]
        print(f"📚 MusicBrainz: {mb_data['artists_found']} artists found")
        if mb_data["unique_countries"] > 0:
            print(
                f"   Countries: {mb_data['unique_countries']} ({mb_data['top_country']} most common)"
            )

    if "audiodb_data" in insights:
        adb_data = insights["audiodb_data"]
        print(f"🎧 AudioDB: {adb_data['artists_found']} artists found")
        if adb_data["unique_genres"] > 0:
            print(f"   Genres: {adb_data['unique_genres']} different genres")
        if adb_data["average_formation_year"]:
            print(f"   Average formation year: {adb_data['average_formation_year']}")

    print(f"\n📁 Data saved to: {data_dir}/")
    print("   • simple_top_artists.csv")
    print("   • simple_top_tracks.csv")
    print("   • musicbrainz_enriched.csv")
    print("   • audiodb_enriched.csv")
    print("   • simple_insights.json")

    print("\n✅ Multi-source integration demo complete!")


if __name__ == "__main__":
    simple_multi_source_demo()
