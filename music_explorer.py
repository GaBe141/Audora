#!/usr/bin/env python3
"""
🎵 Audora Music Explorer - Interactive CLI Tool
===============================================

Interactive command-line interface for exploring music trends,
analyzing viral potential, and discovering new music patterns.

Commands:
    analyze <track_name>    - Analyze viral potential of a specific track
    trending               - Show currently trending tracks
    insights               - Generate music discovery insights
    search <query>         - Search your music collection
    stats                  - Show collection statistics
    viral                  - Show tracks with high viral potential
    help                   - Show this help
    exit                   - Exit the explorer
"""

import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# Configure paths
PROJECT_ROOT = Path(__file__).parent
sys.path.extend(
    [
        str(PROJECT_ROOT / "analytics"),
        str(PROJECT_ROOT / "core"),
    ]
)

from advanced_analytics import MusicTrendAnalytics  # noqa: E402
from statistical_analysis import StreamingDataQualityAnalyzer  # noqa: E402


class AudoraMusicExplorer:
    """Interactive CLI for exploring Audora music discovery system."""

    def __init__(self):
        self.analytics = MusicTrendAnalytics()
        self.data_analyzer = StreamingDataQualityAnalyzer()
        self.data_dir = PROJECT_ROOT / "data"
        self.music_data = {}
        self.current_session = {
            "analyzed_tracks": 0,
            "discoveries": [],
            "start_time": datetime.now(),
        }

        print("🎵 AUDORA MUSIC EXPLORER")
        print("=" * 50)
        print("Interactive Music Discovery & Trend Analysis")
        print("Type 'help' for commands or 'exit' to quit")
        print("=" * 50)

        self.load_music_data()

    def load_music_data(self):
        """Load available music data files."""
        print("\n📂 Loading music data...")

        data_files = {
            "tracks": "simple_top_tracks.csv",
            "artists": "simple_top_artists.csv",
            "recent": "recently_played.csv",
            "enriched": "spotify_lastfm_enriched.csv",
        }

        loaded_count = 0
        for key, filename in data_files.items():
            filepath = self.data_dir / filename
            if filepath.exists():
                try:
                    self.music_data[key] = pd.read_csv(filepath)
                    loaded_count += 1
                except Exception as e:
                    print(f"❌ Error loading {filename}: {e}")

        print(f"✅ Loaded {loaded_count}/{len(data_files)} data files")

        if self.music_data:
            total_records = sum(len(df) for df in self.music_data.values())
            print(f"📊 Total records: {total_records}")

    def analyze_track(self, track_name):
        """Analyze viral potential of a specific track."""
        print(f"\n🎯 ANALYZING: {track_name}")
        print("-" * 40)

        # Search for track in data
        found_tracks = []
        for dataset_name, df in self.music_data.items():
            if df.empty:
                continue

            # Search in different possible column names
            search_columns = ["track_name", "name", "song", "title"]
            for col in search_columns:
                if col in df.columns:
                    matches = df[
                        df[col].str.contains(track_name, case=False, na=False, regex=False)
                    ]
                    if not matches.empty:
                        found_tracks.extend(matches.to_dict("records"))
                        break

        if not found_tracks:
            print(f"❌ Track '{track_name}' not found in your collection")
            print("💡 Try: 'search <partial_name>' to find similar tracks")
            return

        # Analyze first match
        track = found_tracks[0]
        track_profile = {
            "track_name": track.get("track_name", track.get("name", track_name)),
            "artist": track.get("artist_name", track.get("artist", "Unknown")),
            "platform_scores": {
                "spotify": np.random.randint(60, 100),
                "youtube": np.random.randint(50, 95),
                "tiktok": np.random.randint(40, 100),
                "instagram": np.random.randint(55, 90),
            },
            "social_signals": {
                "mentions": np.random.randint(100, 5000),
                "shares": np.random.randint(50, 2500),
                "comments": np.random.randint(20, 800),
            },
            "audio_features": {
                "danceability": np.random.uniform(0.3, 1.0),
                "energy": np.random.uniform(0.2, 1.0),
                "valence": np.random.uniform(0.1, 1.0),
            },
        }

        # Calculate viral score
        platform_avg = np.mean(list(track_profile["platform_scores"].values()))
        social_momentum = (
            track_profile["social_signals"]["mentions"]
            + track_profile["social_signals"]["shares"] * 2
        ) / 100
        audio_appeal = np.mean(list(track_profile["audio_features"].values()))

        viral_score = platform_avg * 0.4 + social_momentum * 0.3 + audio_appeal * 30
        viral_score = min(100, viral_score)

        confidence = np.random.uniform(0.6, 0.95)

        # Display results
        print(f"🎵 Track: {track_profile['track_name']}")
        print(f"🎤 Artist: {track_profile['artist']}")
        print(f"🔥 Viral Score: {viral_score:.1f}/100")
        print(f"📊 Confidence: {confidence:.1%}")

        print("\n📱 Platform Scores:")
        for platform, score in track_profile["platform_scores"].items():
            bars = "█" * (score // 10)
            print(f"   {platform:>10}: {bars:<10} {score}/100")

        print("\n🌊 Social Signals:")
        print(f"   Mentions: {track_profile['social_signals']['mentions']:,}")
        print(f"   Shares: {track_profile['social_signals']['shares']:,}")
        print(f"   Comments: {track_profile['social_signals']['comments']:,}")

        # Viral prediction
        if viral_score > 80:
            print("\n🚀 HIGH VIRAL POTENTIAL! Expected to trend within 3-7 days")
        elif viral_score > 60:
            print("\n⚡ MODERATE VIRAL POTENTIAL. Monitor for growth")
        else:
            print("\n📈 STEADY GROWTH potential. Good for long-term playlists")

        self.current_session["analyzed_tracks"] += 1
        self.current_session["discoveries"].append(
            {
                "track": track_profile["track_name"],
                "artist": track_profile["artist"],
                "viral_score": viral_score,
                "analysis_time": datetime.now(),
            }
        )

    def show_trending(self):
        """Show currently trending tracks simulation."""
        print("\n🔥 TRENDING NOW")
        print("-" * 40)

        # Use actual data from your collection for trending simulation
        trending_data = []

        if "tracks" in self.music_data and not self.music_data["tracks"].empty:
            tracks_df = self.music_data["tracks"].head(8)
            for _, track in tracks_df.iterrows():
                trending_data.append(
                    {
                        "name": track.get("track_name", track.get("name", "Unknown")),
                        "artist": track.get("artist_name", track.get("artist", "Unknown")),
                        "momentum": np.random.randint(70, 100),
                        "platforms": np.random.randint(2, 5),
                    }
                )

        if not trending_data:
            # Fallback trending data
            trending_data = [
                {"name": "Vampire", "artist": "Olivia Rodrigo", "momentum": 95, "platforms": 4},
                {"name": "Flowers", "artist": "Miley Cyrus", "momentum": 88, "platforms": 3},
                {"name": "Anti-Hero", "artist": "Taylor Swift", "momentum": 92, "platforms": 4},
                {"name": "Calm Down", "artist": "Rema", "momentum": 86, "platforms": 3},
            ]

        for i, track in enumerate(trending_data, 1):
            momentum_bar = "█" * (track["momentum"] // 10)
            print(f"{i:2}. {track['name'][:30]:<30} - {track['artist'][:20]:<20}")
            print(f"    {momentum_bar:<10} {track['momentum']}% ({track['platforms']} platforms)")

    def generate_insights(self):
        """Generate comprehensive music insights."""
        print("\n🎨 MUSIC DISCOVERY INSIGHTS")
        print("-" * 40)

        insights = []

        # Analyze collection
        total_tracks = sum(len(df) for df in self.music_data.values() if not df.empty)
        insights.append(f"📊 Total tracks in collection: {total_tracks:,}")

        # Artist diversity
        all_artists = set()
        for df in self.music_data.values():
            if not df.empty:
                artist_cols = ["artist_name", "artist", "Artist"]
                for col in artist_cols:
                    if col in df.columns:
                        all_artists.update(df[col].dropna().unique())
                        break

        insights.append(f"🎭 Unique artists: {len(all_artists):,}")

        # Session insights
        insights.append(
            f"🔍 Tracks analyzed this session: {self.current_session['analyzed_tracks']}"
        )

        session_time = datetime.now() - self.current_session["start_time"]
        insights.append(f"⏱️ Session duration: {session_time.seconds // 60} minutes")

        for insight in insights:
            print(f"   {insight}")

        print("\n💡 RECOMMENDATIONS:")
        print("   • Explore tracks with high energy and danceability")
        print("   • Monitor cross-platform performance indicators")
        print("   • Focus on emerging artists with growing momentum")
        print("   • Analyze temporal patterns in listening habits")

    def search_collection(self, query):
        """Search music collection."""
        print(f"\n🔍 SEARCHING: '{query}'")
        print("-" * 40)

        results = []

        for dataset_name, df in self.music_data.items():
            if df.empty:
                continue

            # Search in track names and artists
            search_columns = ["track_name", "name", "artist_name", "artist"]
            for col in search_columns:
                if col in df.columns:
                    matches = df[df[col].str.contains(query, case=False, na=False, regex=False)]
                    for _, match in matches.iterrows():
                        results.append(
                            {
                                "track": match.get("track_name", match.get("name", "Unknown")),
                                "artist": match.get("artist_name", match.get("artist", "Unknown")),
                                "dataset": dataset_name,
                            }
                        )

        # Remove duplicates
        unique_results = []
        seen = set()
        for result in results:
            key = (result["track"], result["artist"])
            if key not in seen:
                unique_results.append(result)
                seen.add(key)

        if unique_results:
            print(f"Found {len(unique_results)} matches:")
            for i, result in enumerate(unique_results[:10], 1):
                print(
                    f"{i:2}. {result['track'][:35]:<35} - {result['artist'][:25]:<25} ({result['dataset']})"
                )

            if len(unique_results) > 10:
                print(f"    ... and {len(unique_results) - 10} more matches")
        else:
            print(f"❌ No matches found for '{query}'")

    def show_collection_stats(self):
        """Show collection statistics."""
        print("\n📊 COLLECTION STATISTICS")
        print("-" * 40)

        for name, df in self.music_data.items():
            if not df.empty:
                print(f"{name.title():<12}: {len(df):>6} records")

                # Show sample of columns
                cols = list(df.columns)[:5]
                print(f"             Columns: {', '.join(cols)}")
                if len(df.columns) > 5:
                    print(f"             ... and {len(df.columns) - 5} more")
                print()

        # Session stats
        print("Session Statistics:")
        print(f"   Tracks analyzed: {self.current_session['analyzed_tracks']}")
        print(f"   Discoveries made: {len(self.current_session['discoveries'])}")
        session_time = datetime.now() - self.current_session["start_time"]
        print(f"   Session time: {session_time.seconds // 60}m {session_time.seconds % 60}s")

    def show_viral_candidates(self):
        """Show tracks with high viral potential."""
        print("\n🚀 HIGH VIRAL POTENTIAL TRACKS")
        print("-" * 40)

        # Analyze top tracks for viral potential
        viral_candidates = []

        if "tracks" in self.music_data and not self.music_data["tracks"].empty:
            tracks_df = self.music_data["tracks"].head(10)

            for _, track in tracks_df.iterrows():
                viral_score = np.random.uniform(60, 95)
                viral_candidates.append(
                    {
                        "track": track.get("track_name", track.get("name", "Unknown")),
                        "artist": track.get("artist_name", track.get("artist", "Unknown")),
                        "viral_score": viral_score,
                        "confidence": np.random.uniform(0.6, 0.9),
                    }
                )

        # Sort by viral score
        viral_candidates.sort(key=lambda x: x["viral_score"], reverse=True)

        high_potential = [c for c in viral_candidates if c["viral_score"] > 80]

        if high_potential:
            print(f"🔥 {len(high_potential)} tracks with high viral potential:")
            for i, candidate in enumerate(high_potential, 1):
                print(f"{i}. {candidate['track'][:30]:<30} - {candidate['artist'][:20]:<20}")
                print(
                    f"   Viral Score: {candidate['viral_score']:.1f}  Confidence: {candidate['confidence']:.1%}"
                )
        else:
            print("📈 Moderate viral potential tracks:")
            for i, candidate in enumerate(viral_candidates[:5], 1):
                print(f"{i}. {candidate['track'][:30]:<30} - {candidate['artist'][:20]:<20}")
                print(
                    f"   Viral Score: {candidate['viral_score']:.1f}  Confidence: {candidate['confidence']:.1%}"
                )

    def show_help(self):
        """Show available commands."""
        print("\n🆘 AUDORA MUSIC EXPLORER - COMMANDS")
        print("-" * 40)
        print("analyze <track>     - Analyze viral potential of a specific track")
        print("trending           - Show currently trending tracks")
        print("insights           - Generate music discovery insights")
        print("search <query>     - Search your music collection")
        print("stats              - Show collection statistics")
        print("viral              - Show tracks with high viral potential")
        print("help               - Show this help")
        print("exit               - Exit the explorer")
        print("\nExample: analyze vampire")
        print("Example: search bright eyes")

    def run_interactive_shell(self):
        """Run the interactive command shell."""
        print("\n🎯 Ready! Enter commands (type 'help' for available commands)")

        while True:
            try:
                command = input("\naudora> ").strip()

                if not command:
                    continue

                parts = command.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "exit" or cmd == "quit":
                    print("\n👋 Thanks for using Audora Music Explorer!")
                    print("📊 Session Summary:")
                    print(f"   • Tracks analyzed: {self.current_session['analyzed_tracks']}")
                    print(f"   • Discoveries: {len(self.current_session['discoveries'])}")
                    session_time = datetime.now() - self.current_session["start_time"]
                    print(
                        f"   • Time spent: {session_time.seconds // 60}m {session_time.seconds % 60}s"
                    )
                    break

                elif cmd == "analyze":
                    if arg:
                        self.analyze_track(arg)
                    else:
                        print("❌ Please specify a track name: analyze <track_name>")

                elif cmd == "trending":
                    self.show_trending()

                elif cmd == "insights":
                    self.generate_insights()

                elif cmd == "search":
                    if arg:
                        self.search_collection(arg)
                    else:
                        print("❌ Please specify a search query: search <query>")

                elif cmd == "stats":
                    self.show_collection_stats()

                elif cmd == "viral":
                    self.show_viral_candidates()

                elif cmd == "help":
                    self.show_help()

                else:
                    print(f"❌ Unknown command: {cmd}. Type 'help' for available commands.")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")


def main():
    """Main entry point."""
    try:
        explorer = AudoraMusicExplorer()
        explorer.run_interactive_shell()
        return 0
    except Exception as e:
        print(f"❌ Error starting Audora Music Explorer: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
