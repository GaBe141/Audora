"""Multi-source music data integration combining Spotify, Last.fm, MusicBrainz, AudioDB, and Charts."""

from pathlib import Path
from typing import Any

import pandas as pd

from core.utils import save_dataframe, write_json

from .audiodb_integration import (
    analyze_genre_evolution_with_audiodb,
    enrich_spotify_artists_with_audiodb,
)
from .auth import get_client
from .fetch import fetch_top_artists, fetch_top_tracks
from .lastfm_integration import enrich_spotify_artists_with_lastfm, get_lastfm_client
from .multi_source_viz import MultiSourceVisualizer
from .musicbrainz_integration import (
    analyze_artist_relationships,
    enrich_spotify_artists_with_musicbrainz,
)
from .spotify_charts_integration import compare_personal_vs_charts


def collect_all_data() -> dict[str, pd.DataFrame]:
    """Collect data from all available sources."""
    print("🎵 Starting multi-source data collection...")

    # Initialize data storage
    all_data = {}

    # 1. Get Spotify personal data
    print("\n1️⃣ Collecting Spotify personal data...")
    try:
        spotify_client = get_client()

        # Get top artists and tracks
        top_artists_df = fetch_top_artists(spotify_client, time_range="medium_term", limit=50)
        top_tracks_df = fetch_top_tracks(spotify_client, time_range="medium_term", limit=50)

        all_data["spotify_top_artists"] = top_artists_df
        all_data["spotify_top_tracks"] = top_tracks_df

        print(
            f"✅ Collected {len(top_artists_df)} artists and {len(top_tracks_df)} tracks from Spotify"
        )

    except Exception as e:
        print(f"❌ Error collecting Spotify data: {e}")
        return {}

    # 2. Enrich with Last.fm global trends
    print("\n2️⃣ Enriching with Last.fm global trends...")
    try:
        lastfm_client = get_lastfm_client()
        if lastfm_client:
            enriched_lastfm = enrich_spotify_artists_with_lastfm(top_artists_df)
            all_data["spotify_lastfm_enriched"] = enriched_lastfm
            print("✅ Enhanced data with Last.fm global trends")
        else:
            print("⚠️ Last.fm client not available - skipping")
            all_data["spotify_lastfm_enriched"] = top_artists_df
    except Exception as e:
        print(f"❌ Error with Last.fm integration: {e}")
        all_data["spotify_lastfm_enriched"] = top_artists_df

    # 3. Enrich with MusicBrainz metadata
    print("\n3️⃣ Enriching with MusicBrainz metadata...")
    try:
        enriched_mb = enrich_spotify_artists_with_musicbrainz(all_data["spotify_lastfm_enriched"])
        all_data["spotify_musicbrainz_enriched"] = enriched_mb

        # Analyze artist relationships
        artist_names = top_artists_df["artist_name"].tolist()[
            :20
        ]  # Limit to top 20 for performance
        relationships = analyze_artist_relationships(artist_names)
        all_data["artist_relationships"] = relationships["network"]
        all_data["relationship_summary"] = relationships["relationship_summary"]

        print("✅ Enhanced data with MusicBrainz metadata and relationships")
    except Exception as e:
        print(f"❌ Error with MusicBrainz integration: {e}")
        all_data["spotify_musicbrainz_enriched"] = all_data["spotify_lastfm_enriched"]
        all_data["artist_relationships"] = pd.DataFrame()

    # 4. Enrich with AudioDB profiles
    print("\n4️⃣ Enriching with AudioDB artist profiles...")
    try:
        enriched_adb = enrich_spotify_artists_with_audiodb(all_data["spotify_musicbrainz_enriched"])
        all_data["fully_enriched_artists"] = enriched_adb

        # Analyze genre evolution
        artist_names = top_artists_df["artist_name"].tolist()[:15]  # Limit for performance
        genre_evolution = analyze_genre_evolution_with_audiodb(artist_names)
        all_data["genre_evolution"] = genre_evolution["careers"]
        all_data["album_timeline"] = genre_evolution["albums"]

        print("✅ Enhanced data with AudioDB profiles and career analysis")
    except Exception as e:
        print(f"❌ Error with AudioDB integration: {e}")
        all_data["fully_enriched_artists"] = all_data["spotify_musicbrainz_enriched"]
        all_data["genre_evolution"] = pd.DataFrame()

    # 5. Compare with Spotify Charts
    print("\n5️⃣ Comparing with global Spotify Charts...")
    try:
        chart_comparison = compare_personal_vs_charts(top_tracks_df)
        all_data["chart_comparison"] = chart_comparison["comparison"]
        all_data["chart_matches"] = chart_comparison["matches"]
        all_data["global_charts"] = chart_comparison["global_charts"]

        print("✅ Compared personal taste with global charts")
    except Exception as e:
        print(f"❌ Error with Charts integration: {e}")
        all_data["chart_comparison"] = pd.DataFrame()
        all_data["chart_matches"] = pd.DataFrame()

    return all_data


def analyze_cross_platform_insights(all_data: dict[str, pd.DataFrame]) -> dict[str, Any]:
    """Analyze insights across all platforms."""
    print("\n🔍 Analyzing cross-platform insights...")

    insights = {}

    # 1. Multi-platform mainstream score
    if not all_data.get("chart_comparison", pd.DataFrame()).empty:
        spotify_mainstream = all_data["chart_comparison"]["mainstream_score_percent"].iloc[0]

        # Add Last.fm mainstream score if available
        lastfm_mainstream = 0
        if (
            "spotify_lastfm_enriched" in all_data
            and "lastfm_global_rank" in all_data["spotify_lastfm_enriched"].columns
        ):
            # Calculate Last.fm mainstream score (artists in top global)
            total_artists = len(all_data["spotify_lastfm_enriched"])
            mainstream_artists = len(
                all_data["spotify_lastfm_enriched"][
                    all_data["spotify_lastfm_enriched"]["lastfm_global_rank"] <= 100
                ]
            )
            lastfm_mainstream = (
                (mainstream_artists / total_artists * 100) if total_artists > 0 else 0
            )

        insights["mainstream_analysis"] = {
            "spotify_charts_mainstream_percent": spotify_mainstream,
            "lastfm_mainstream_percent": lastfm_mainstream,
            "average_mainstream_score": (spotify_mainstream + lastfm_mainstream) / 2,
        }

    # 2. Geographic diversity analysis
    if (
        "fully_enriched_artists" in all_data
        and "country" in all_data["fully_enriched_artists"].columns
    ):
        country_distribution = all_data["fully_enriched_artists"]["country"].value_counts()
        insights["geographic_diversity"] = {
            "unique_countries": len(country_distribution),
            "top_country": country_distribution.index[0] if len(country_distribution) > 0 else None,
            "top_country_percentage": (
                (country_distribution.iloc[0] / country_distribution.sum() * 100)
                if len(country_distribution) > 0
                else 0
            ),
            "country_distribution": country_distribution.to_dict(),
        }

    # 3. Career era analysis
    if "genre_evolution" in all_data and not all_data["genre_evolution"].empty:
        careers_df = all_data["genre_evolution"]
        if "formed_year" in careers_df.columns:
            careers_df["formed_year"] = pd.to_numeric(careers_df["formed_year"], errors="coerce")
            era_analysis = careers_df.dropna(subset=["formed_year"])

            if not era_analysis.empty:
                insights["era_analysis"] = {
                    "earliest_artist_year": int(era_analysis["formed_year"].min()),
                    "latest_artist_year": int(era_analysis["formed_year"].max()),
                    "average_formation_year": int(era_analysis["formed_year"].mean()),
                    "era_span_years": int(
                        era_analysis["formed_year"].max() - era_analysis["formed_year"].min()
                    ),
                }

    # 4. Relationship network analysis
    if "artist_relationships" in all_data and not all_data["artist_relationships"].empty:
        relationships_df = all_data["artist_relationships"]
        insights["network_analysis"] = {
            "total_relationships": len(relationships_df),
            "unique_artists_in_network": len(
                set(
                    relationships_df["source_artist"].tolist()
                    + relationships_df["target_artist"].tolist()
                )
            ),
            "most_connected_artist": (
                relationships_df["source_artist"].mode().iloc[0]
                if len(relationships_df) > 0
                else None
            ),
            "relationship_types": relationships_df["relationship_type"].value_counts().to_dict(),
        }

    # 5. Data coverage analysis
    coverage_stats = {}
    for source, df in all_data.items():
        if isinstance(df, pd.DataFrame):
            coverage_stats[source] = {
                "total_records": len(df),
                "columns": len(df.columns) if hasattr(df, "columns") else 0,
                "non_null_percentage": (
                    (df.count().sum() / (len(df) * len(df.columns)) * 100)
                    if len(df) > 0 and hasattr(df, "columns")
                    else 0
                ),
            }

    insights["data_coverage"] = coverage_stats

    return insights


def save_all_data(all_data: dict[str, pd.DataFrame], insights: dict) -> None:
    """Save all collected data and insights using centralized utilities."""
    print("\n💾 Saving multi-source analysis results...")

    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    # Save DataFrames as CSV
    for name, df in all_data.items():
        if isinstance(df, pd.DataFrame) and not df.empty:
            filepath = data_dir / f"{name}.csv"
            save_dataframe(df, filepath)
            print(f"Saved {filepath}")

    # Save insights as JSON
    insights_file = data_dir / "multi_source_insights.json"
    write_json(insights_file, insights)
    print(f"Saved {insights_file}")


def main():
    """Main multi-source analysis pipeline."""
    print("🎵 Multi-Source Music Data Analysis")
    print("=" * 50)
    print("Integrating: Spotify + Last.fm + MusicBrainz + AudioDB + Charts")
    print("=" * 50)

    # Collect all data
    all_data = collect_all_data()

    if not all_data:
        print("❌ Failed to collect data. Check your API configurations.")
        return

    # Analyze cross-platform insights
    insights = analyze_cross_platform_insights(all_data)

    # Save everything
    save_all_data(all_data, insights)

    # Generate visualizations
    print("\n🎨 Generating multi-source visualizations...")
    try:
        visualizer = MultiSourceVisualizer(all_data, insights)
        visualizer.create_all_visualizations()
        print("✅ Generated comprehensive visualization suite")
    except Exception as e:
        print(f"❌ Error generating visualizations: {e}")

    # Print summary
    print("\n" + "=" * 50)
    print("📊 MULTI-SOURCE ANALYSIS SUMMARY")
    print("=" * 50)

    if insights.get("mainstream_analysis"):
        mainstream = insights["mainstream_analysis"]
        print(f"🎯 Mainstream Score: {mainstream['average_mainstream_score']:.1f}%")
        print(f"   - Spotify Charts: {mainstream['spotify_charts_mainstream_percent']:.1f}%")
        print(f"   - Last.fm Global: {mainstream['lastfm_mainstream_percent']:.1f}%")

    if insights.get("geographic_diversity"):
        geo = insights["geographic_diversity"]
        print(f"🌍 Geographic Diversity: {geo['unique_countries']} countries")
        if geo["top_country"]:
            print(f"   - Top Country: {geo['top_country']} ({geo['top_country_percentage']:.1f}%)")

    if insights.get("era_analysis"):
        era = insights["era_analysis"]
        print(
            f"📅 Era Span: {era['earliest_artist_year']}-{era['latest_artist_year']} ({era['era_span_years']} years)"
        )
        print(f"   - Average Formation Year: {era['average_formation_year']}")

    if insights.get("network_analysis"):
        network = insights["network_analysis"]
        print(f"🕸️ Artist Network: {network['total_relationships']} relationships")
        if network["most_connected_artist"]:
            print(f"   - Most Connected: {network['most_connected_artist']}")

    # Data coverage summary
    if insights.get("data_coverage"):
        coverage = insights["data_coverage"]
        total_records = sum(stats["total_records"] for stats in coverage.values())
        print(f"📊 Total Data Points: {total_records:,}")
        print(f"   - Sources Integrated: {len(coverage)}")

    print("\n✅ Multi-source analysis complete!")
    print("Check the 'data/' directory for detailed results and visualizations.")


if __name__ == "__main__":
    main()
