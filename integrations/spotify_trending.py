"""
Integration module for trending schema with Spotify streaming data.
Connects real-time streaming data to trending analysis framework.
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict

import numpy as np
import pandas as pd

from .trending_schema import TrendCategory, TrendDirection, TrendingSchema


class SpotifyTrendingIntegration:
    """Integration between Spotify data and trending schema."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.trending_schema = TrendingSchema()

        # Mapping of data files to trend categories
        self.file_mappings = {
            "simple_top_tracks.csv": TrendCategory.TRACK,
            "simple_top_artists.csv": TrendCategory.ARTIST,
            "lastfm_global_tracks.csv": TrendCategory.TRACK,
            "lastfm_global_artists.csv": TrendCategory.ARTIST,
            "recently_played.csv": TrendCategory.TRACK,
            "spotify_lastfm_enriched.csv": TrendCategory.ARTIST,
        }

        # Value extraction strategies for different files
        self.value_extractors = {
            "simple_top_tracks.csv": self._extract_track_popularity,
            "simple_top_artists.csv": self._extract_artist_followers,
            "lastfm_global_tracks.csv": self._extract_lastfm_playcount,
            "lastfm_global_artists.csv": self._extract_lastfm_listeners,
            "recently_played.csv": self._extract_play_frequency,
            "spotify_lastfm_enriched.csv": self._extract_combined_popularity,
        }

    class LoadResults(TypedDict):
        files_processed: int
        items_added: int
        categories_populated: set[str]
        processing_errors: list[str]

    def load_and_process_data(self) -> "SpotifyTrendingIntegration.LoadResults":
        """Load all available data and populate trending schema."""
        print("📊 Loading Spotify data for trending analysis...")

        results: SpotifyTrendingIntegration.LoadResults = {
            "files_processed": 0,
            "items_added": 0,
            "categories_populated": set(),
            "processing_errors": [],
        }

        for filename, category in self.file_mappings.items():
            file_path = self.data_dir / filename

            if not file_path.exists():
                print(f"   ⚠️ {filename}: File not found")
                continue

            try:
                df = pd.read_csv(file_path)
                extractor = self.value_extractors.get(filename)

                if extractor:
                    items_added = extractor(df, category)
                    results["items_added"] += items_added
                    results["categories_populated"].add(category.value)
                    print(f"   ✅ {filename}: {items_added} items processed")
                else:
                    print(f"   ⚠️ {filename}: No extractor defined")

                results["files_processed"] += 1

            except Exception as e:
                error_msg = f"Error processing {filename}: {str(e)}"
                results["processing_errors"].append(error_msg)
                print(f"   ❌ {filename}: {error_msg}")

        print("\n📈 Trending data loading complete:")
        print(f"   Files processed: {results['files_processed']}")
        print(f"   Items added: {results['items_added']}")
        print(f"   Categories: {', '.join(results['categories_populated'])}")

        return results

    def _extract_track_popularity(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from Spotify tracks."""
        items_added = 0

        for _, row in df.iterrows():
            if "name" in row and "popularity" in row:
                # Use track name as ID, popularity as value
                name_str = str(row["name"])
                item_id = f"track_{row.get('id', name_str.replace(' ', '_'))}"
                name = name_str
                value = float(row["popularity"])

                # Add some temporal variation (simulate different time points)
                base_time = datetime.now() - timedelta(days=30)
                for i in range(5):  # 5 data points over 30 days
                    timestamp = base_time + timedelta(days=i * 6)
                    # Add some variation to simulate changing popularity
                    varied_value = value + np.random.normal(0, value * 0.1)
                    varied_value = max(0, varied_value)  # Ensure non-negative

                    self.trending_schema.add_data_point(
                        item_id=item_id,
                        name=name,
                        category=category,
                        value=varied_value,
                        timestamp=timestamp,
                        metadata={
                            "source": "spotify_tracks",
                            "original_popularity": value,
                            "artist": row.get("artist", "Unknown"),
                        },
                    )

                items_added += 1

        return items_added

    def _extract_artist_followers(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from Spotify artists."""
        items_added = 0

        for _, row in df.iterrows():
            if "name" in row and "followers" in row:
                name_str = str(row["name"])
                item_id = f"artist_{row.get('id', name_str.replace(' ', '_'))}"
                name = name_str
                value = float(row["followers"])

                # Simulate follower growth over time
                base_time = datetime.now() - timedelta(days=60)
                base_followers = value * 0.8  # Start with 80% of current followers

                for i in range(8):  # 8 data points over 60 days
                    timestamp = base_time + timedelta(days=i * 7)
                    # Simulate gradual growth
                    growth_factor = 1 + (i * 0.025)  # 2.5% growth per week
                    simulated_value = base_followers * growth_factor

                    self.trending_schema.add_data_point(
                        item_id=item_id,
                        name=name,
                        category=category,
                        value=simulated_value,
                        timestamp=timestamp,
                        metadata={
                            "source": "spotify_artists",
                            "current_followers": value,
                            "genres": row.get("genres", ""),
                            "rank": row.get("rank", None),
                        },
                    )

                items_added += 1

        return items_added

    def _extract_lastfm_playcount(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from Last.fm tracks."""
        items_added = 0

        for _, row in df.iterrows():
            if "name" in row and "playcount" in row:
                name_str = str(row["name"])
                item_id = f"lastfm_track_{name_str.replace(' ', '_')}"
                name = f"{name_str} - {row.get('artist', 'Unknown')}"
                value = float(row["playcount"])

                # Simulate playcount evolution
                base_time = datetime.now() - timedelta(days=14)

                for i in range(7):  # Daily data for 2 weeks
                    timestamp = base_time + timedelta(days=i * 2)
                    # Simulate varying playcounts
                    daily_variation = np.random.uniform(0.9, 1.1)
                    simulated_value = value * daily_variation

                    self.trending_schema.add_data_point(
                        item_id=item_id,
                        name=name,
                        category=category,
                        value=simulated_value,
                        timestamp=timestamp,
                        metadata={
                            "source": "lastfm_global",
                            "artist": row.get("artist", "Unknown"),
                            "listeners": row.get("listeners", 0),
                            "rank": row.get("rank", None),
                        },
                    )

                items_added += 1

        return items_added

    def _extract_lastfm_listeners(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from Last.fm artists."""
        items_added = 0

        for _, row in df.iterrows():
            if "name" in row and "listeners" in row:
                name_str = str(row["name"])
                item_id = f"lastfm_artist_{name_str.replace(' ', '_')}"
                name = name_str
                value = float(row["listeners"])

                # Simulate listener growth patterns
                base_time = datetime.now() - timedelta(days=21)

                for i in range(7):  # Weekly data for 3 weeks
                    timestamp = base_time + timedelta(days=i * 3)
                    # Some artists growing, some stable, some declining
                    trend_factor = np.random.choice([0.95, 1.0, 1.05], p=[0.2, 0.6, 0.2])
                    simulated_value = value * (trend_factor**i)

                    self.trending_schema.add_data_point(
                        item_id=item_id,
                        name=name,
                        category=category,
                        value=simulated_value,
                        timestamp=timestamp,
                        metadata={
                            "source": "lastfm_artists",
                            "playcount": row.get("playcount", 0),
                            "rank": row.get("rank", None),
                        },
                    )

                items_added += 1

        return items_added

    def _extract_play_frequency(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from recently played tracks."""
        items_added = 0

        if "track_name" not in df.columns:
            return 0

        # Count play frequency by track
        track_counts = df["track_name"].value_counts()

        for track_name, play_count in track_counts.head(20).items():  # Top 20 most played
            track_name_str = str(track_name)
            item_id = f"recent_track_{track_name_str.replace(' ', '_')}"

            # Get artist info if available
            track_info = df[df["track_name"] == track_name].iloc[0]
            artist_name = track_info.get("artist_name", "Unknown")
            name = f"{track_name_str} - {artist_name}"

            # Use play count as trending value
            base_time = datetime.now() - timedelta(days=7)

            for i in range(7):  # Daily play counts for a week
                timestamp = base_time + timedelta(days=i)
                # Simulate daily variations in play counts
                daily_plays = max(1, int(play_count / 7 * np.random.uniform(0.5, 1.5)))

                self.trending_schema.add_data_point(
                    item_id=item_id,
                    name=name,
                    category=category,
                    value=float(daily_plays),
                    timestamp=timestamp,
                    metadata={
                        "source": "recently_played",
                        "total_plays": int(play_count),
                        "artist": artist_name,
                    },
                )

            items_added += 1

        return items_added

    def _extract_combined_popularity(self, df: pd.DataFrame, category: TrendCategory) -> int:
        """Extract trending data from enriched Spotify + Last.fm data."""
        items_added = 0

        for _, row in df.iterrows():
            if "name" in row:
                name_str = str(row["name"])
                item_id = f"enriched_artist_{name_str.replace(' ', '_')}"
                name = name_str

                # Combine multiple metrics for trending value
                spotify_followers = row.get("followers", 0)
                lastfm_listeners = row.get("lastfm_listeners", 0)

                # Create combined popularity score
                combined_score = spotify_followers * 0.7 + lastfm_listeners * 0.3

                if combined_score > 0:
                    base_time = datetime.now() - timedelta(days=45)

                    for i in range(9):  # Data points over 45 days
                        timestamp = base_time + timedelta(days=i * 5)
                        # Simulate combined metric evolution
                        evolution_factor = np.random.uniform(0.95, 1.05)
                        simulated_value = combined_score * (evolution_factor**i)

                        self.trending_schema.add_data_point(
                            item_id=item_id,
                            name=name,
                            category=category,
                            value=simulated_value,
                            timestamp=timestamp,
                            metadata={
                                "source": "enriched_data",
                                "spotify_followers": spotify_followers,
                                "lastfm_listeners": lastfm_listeners,
                                "combined_score": combined_score,
                            },
                        )

                    items_added += 1

        return items_added

    def analyze_trending_insights(self) -> dict[str, Any]:
        """Generate comprehensive trending insights."""
        print("\n🔥 Analyzing trending patterns...")

        category_analysis: dict[str, Any] = {}
        viral_content: list[dict[str, Any]] = []
        emerging_trends: list[dict[str, Any]] = []
        predictions: dict[str, Any] = {}
        top_movers: dict[str, Any] = {}

        insights: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "category_analysis": category_analysis,
            "viral_content": viral_content,
            "emerging_trends": emerging_trends,
            "predictions": predictions,
            "top_movers": top_movers,
        }

        # Analyze each category
        for category in TrendCategory:
            category_items = self.trending_schema.get_trending_by_category(category)

            if not category_items:
                continue

            print(f"   📊 {category.value.title()}: {len(category_items)} trending items")

            # Category analysis
            directions: dict[str, int] = {}
            for direction in TrendDirection:
                count = len([item for item in category_items if item.direction == direction])
                if count > 0:
                    directions[direction.value] = count

            category_analysis[category.value] = {
                "total_items": len(category_items),
                "directions": directions,
                "top_trending": [
                    {
                        "name": item.name,
                        "direction": item.direction.value,
                        "growth_rate": item.metrics.growth_rate,
                        "trend_strength": item.metrics.trend_strength,
                    }
                    for item in category_items[:5]
                ],
            }

            # Find top movers
            if category_items:
                top_gainer = max(category_items, key=lambda x: x.metrics.growth_rate)
                top_movers[f"{category.value}_top_gainer"] = {
                    "name": top_gainer.name,
                    "growth_rate": top_gainer.metrics.growth_rate,
                    "direction": top_gainer.direction.value,
                }

        # Get viral content across all categories
        viral_items = self.trending_schema.get_viral_content()
        viral_content[:] = [
            {
                "name": item.name,
                "category": item.category.value,
                "growth_rate": item.metrics.growth_rate,
                "peak_value": item.metrics.peak_value,
            }
            for item in viral_items
        ]

        # Get emerging trends
        emerging_items = self.trending_schema.get_emerging_trends()
        emerging_trends[:] = [
            {
                "name": item.name,
                "category": item.category.value,
                "momentum": item.metrics.momentum,
                "trend_strength": item.metrics.trend_strength,
            }
            for item in emerging_items
        ]

        # Generate predictions for top items
        all_trending = []
        for category in TrendCategory:
            all_trending.extend(self.trending_schema.get_trending_by_category(category))

        # Get top 3 trending items for predictions
        top_trending = sorted(
            all_trending,
            key=lambda x: x.metrics.trend_strength * abs(x.metrics.growth_rate),
            reverse=True,
        )[:3]

        for item in top_trending:
            prediction = self.trending_schema.predict_trend_continuation(item.item_id)
            if prediction:
                predictions[item.item_id] = prediction

        # Summary statistics
        insights["summary"] = {
            "total_trending_items": len(all_trending),
            "viral_items": len(viral_items),
            "emerging_trends": len(emerging_items),
            "categories_with_data": len(list(category_analysis.keys())),
            "predictions_generated": len(predictions),
        }

        return insights

    def create_trending_report(self, output_dir: str = "data/trending") -> str:
        """Create comprehensive trending analysis report."""
        print("\n📋 Creating trending analysis report...")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Generate insights
        insights = self.analyze_trending_insights()

        # Export trending snapshot
        snapshot = self.trending_schema.export_trending_snapshot(
            str(output_path / "trending_snapshot.json")
        )

        # Create comprehensive report
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "spotify_trending_analysis",
                "data_sources": list(self.file_mappings.keys()),
            },
            "executive_summary": insights["summary"],
            "trending_insights": insights,
            "detailed_snapshot": snapshot,
        }

        # Save main report using centralized utility
        from core.utils import save_report

        saved_path = save_report(
            report,
            filename="spotify_trending_report.json",
            prefix="spotify_trending",
            output_dir=str(output_path),
            add_timestamp=False,
        )

        # Create text summary
        summary_file = output_path / "trending_summary.txt"
        self._create_text_summary(insights, summary_file)

        print(f"   ✅ Report saved to {saved_path}")
        print(f"   ✅ Summary saved to {summary_file}")

        return str(output_path)

    def _create_text_summary(self, insights: dict[str, Any], output_file: Path):
        """Create human-readable trending summary."""
        with output_file.open("w", encoding="utf-8") as f:
            f.write("SPOTIFY TRENDING ANALYSIS REPORT\n")
            f.write("=" * 40 + "\n\n")

            f.write(f"Generated: {insights['timestamp']}\n\n")

            # Summary
            summary = insights["summary"]
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Trending Items: {summary['total_trending_items']}\n")
            f.write(f"Viral Content: {summary['viral_items']}\n")
            f.write(f"Emerging Trends: {summary['emerging_trends']}\n")
            f.write(f"Categories Analyzed: {summary['categories_with_data']}\n\n")

            # Viral content
            if insights["viral_content"]:
                f.write("VIRAL CONTENT 🚀\n")
                f.write("-" * 20 + "\n")
                for item in insights["viral_content"]:
                    f.write(f"🔥 {item['name']} ({item['category']})\n")
                    f.write(f"   Growth: +{item['growth_rate']:.1f}%\n")
                f.write("\n")

            # Emerging trends
            if insights["emerging_trends"]:
                f.write("EMERGING TRENDS 🌱\n")
                f.write("-" * 20 + "\n")
                for item in insights["emerging_trends"]:
                    f.write(f"📈 {item['name']} ({item['category']})\n")
                    f.write(f"   Momentum: {item['momentum']:.2f}\n")
                f.write("\n")

            # Top movers by category
            f.write("TOP MOVERS BY CATEGORY\n")
            f.write("-" * 30 + "\n")
            for category, data in insights["category_analysis"].items():
                f.write(f"\n{category.upper()}:\n")
                for item in data["top_trending"][:3]:
                    direction_emoji = (
                        "📈"
                        if "rising" in item["direction"]
                        else "🚀"
                        if "viral" in item["direction"]
                        else "📊"
                    )
                    f.write(f"  {direction_emoji} {item['name']}\n")
                    f.write(
                        f"     Growth: {item['growth_rate']:.1f}% | Strength: {item['trend_strength']:.2f}\n"
                    )


def main():
    """Main function to demonstrate trending schema integration."""
    print("🔥 Spotify Trending Schema Integration")
    print("=" * 50)

    # Initialize integration
    integration = SpotifyTrendingIntegration()

    # Load and process data
    results = integration.load_and_process_data()

    if results["items_added"] == 0:
        print("\n❌ No data found. Please run data collection first:")
        print("   python simple_multi_source_demo.py")
        return

    # Create trending report
    report_path = integration.create_trending_report()

    # Display key insights
    insights = integration.analyze_trending_insights()

    print("\n🎯 TRENDING ANALYSIS SUMMARY")
    print("=" * 40)

    summary = insights["summary"]
    print(f"📊 Total trending items: {summary['total_trending_items']}")
    print(f"🚀 Viral content: {summary['viral_items']}")
    print(f"🌱 Emerging trends: {summary['emerging_trends']}")

    # Show viral content
    if insights["viral_content"]:
        print("\n🔥 Viral Content:")
        for item in insights["viral_content"][:3]:
            print(f"   🚀 {item['name']}: +{item['growth_rate']:.0f}% growth")

    # Show emerging trends
    if insights["emerging_trends"]:
        print("\n📈 Emerging Trends:")
        for item in insights["emerging_trends"][:3]:
            print(f"   🌱 {item['name']}: {item['momentum']:.2f} momentum")

    # Show predictions
    if insights["predictions"]:
        print("\n🔮 Trend Predictions:")
        for item_id, prediction in list(insights["predictions"].items())[:2]:
            print(f"   📊 {item_id}: {prediction['expected_direction']} trend")
            print(f"      Confidence: {prediction['confidence']:.2f}")

    print(f"\n✅ Full trending analysis available in: {report_path}")
    print("🎵 Trending schema integration complete!")


if __name__ == "__main__":
    main()
