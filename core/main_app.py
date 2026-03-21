"""
Comprehensive Multi-Platform Music Discovery Application.
Integrates all social media APIs for Gen Z/Alpha music trend analysis.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from integrations.api_config import SocialAPIManager
from integrations.extended_platforms import ExtendedSocialDiscoveryEngine
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine
from integrations.trending_schema import TrendingSchema


class ComprehensiveMusicDiscoveryApp:
    """Main application orchestrating all music discovery systems."""

    def __init__(self, config_file: str = "config/social_apis.json"):
        """Initialize the comprehensive music discovery application."""
        print("🎵 Initializing Comprehensive Music Discovery System")
        print("=" * 60)

        # Initialize API manager
        self.api_manager = SocialAPIManager(config_file)

        # Initialize discovery engines
        self.main_engine = None
        self.extended_engine = None
        self.trending_schema = TrendingSchema()

        # Application state
        self.last_discovery_run: datetime | None = None
        self.discovery_cache: dict[str, Any] = {}
        self.analytics_data: list[Any] = []

        self._initialize_engines()

    def _initialize_engines(self):
        """Initialize discovery engines based on available API credentials."""
        print("\n🔧 Initializing Discovery Engines...")

        # Get API configurations
        main_config = {}
        extended_config = {}

        for platform in ["tiktok", "youtube", "twitter", "instagram"]:
            api_config = self.api_manager.get_config(platform)
            if api_config and api_config.enabled:
                if platform == "tiktok":
                    main_config["tiktok_api_key"] = api_config.api_key
                    main_config["tiktok_secret"] = api_config.secret_key
                elif platform == "youtube":
                    main_config["youtube_api_key"] = api_config.api_key
                elif platform == "twitter":
                    main_config["twitter_bearer_token"] = api_config.access_token
                elif platform == "instagram":
                    main_config["instagram_access_token"] = api_config.access_token

        for platform in ["reddit", "tumblr", "soundcloud", "discord"]:
            api_config = self.api_manager.get_config(platform)
            if api_config and api_config.enabled:
                extended_config[platform] = {
                    "client_id": api_config.api_key,
                    "client_secret": api_config.secret_key,
                    "consumer_key": api_config.api_key,
                    "consumer_secret": api_config.secret_key,
                    "bot_token": api_config.access_token,
                }

        # Initialize engines
        if main_config:
            self.main_engine = SocialMusicDiscoveryEngine(main_config)
            print(f"   ✅ Main Engine: {len(main_config)} platforms configured")
        else:
            print("   ⚠️ Main Engine: No API credentials configured")

        if extended_config:
            self.extended_engine = ExtendedSocialDiscoveryEngine(extended_config)
            print(f"   ✅ Extended Engine: {len(extended_config)} platforms configured")
        else:
            print("   ⚠️ Extended Engine: No API credentials configured")

    async def run_full_discovery(self, region: str = "US") -> dict[str, Any]:
        """Run comprehensive music discovery across all platforms."""
        print(f"\n🔍 Starting Full Music Discovery for {region}")
        print("=" * 60)

        discovery_results = {
            "timestamp": datetime.now().isoformat(),
            "region": region,
            "mainstream_platforms": {},
            "underground_platforms": {},
            "cross_platform_analysis": {},
            "trending_predictions": {},
            "recommendations": [],
        }

        # Run mainstream platform discovery
        if self.main_engine:
            print("\n📱 Discovering from Mainstream Platforms...")
            try:
                mainstream_report = await self.main_engine.generate_discovery_report(region)
                discovery_results["mainstream_platforms"] = mainstream_report
                print(
                    f"   ✅ Mainstream: {mainstream_report.get('total_songs_discovered', 0)} songs found"
                )
            except Exception as e:
                print(f"   ❌ Mainstream discovery error: {e}")
                discovery_results["mainstream_platforms"] = {"error": str(e)}

        # Run underground platform discovery
        if self.extended_engine:
            print("\n🎯 Discovering from Underground Platforms...")
            try:
                underground_report = await self.extended_engine.generate_comprehensive_report()
                discovery_results["underground_platforms"] = underground_report
                print(
                    f"   ✅ Underground: {underground_report.get('total_underground_songs', 0)} songs found"
                )
            except Exception as e:
                print(f"   ❌ Underground discovery error: {e}")
                discovery_results["underground_platforms"] = {"error": str(e)}

        # Cross-platform analysis
        discovery_results["cross_platform_analysis"] = self._analyze_cross_platform_trends(
            discovery_results
        )

        # Generate predictions
        discovery_results["trending_predictions"] = self._generate_trending_predictions(
            discovery_results
        )

        # Generate comprehensive recommendations
        discovery_results["recommendations"] = self._generate_comprehensive_recommendations(
            discovery_results
        )

        # Cache results
        self.discovery_cache[region] = discovery_results
        self.last_discovery_run = datetime.now()

        print("\n✅ Full Discovery Complete!")
        return discovery_results

    def _analyze_cross_platform_trends(self, discovery_results: dict[str, Any]) -> dict[str, Any]:
        """Analyze trends that appear across multiple platforms."""
        print("\n🔄 Analyzing Cross-Platform Trends...")

        mainstream_songs = set()
        underground_songs = set()

        # Extract song identifiers from mainstream platforms
        mainstream_data = discovery_results.get("mainstream_platforms", {})
        if "platform_breakdown" in mainstream_data:
            for platform, songs in mainstream_data["platform_breakdown"].items():
                for song in songs:
                    if hasattr(song, "artist_name") and hasattr(song, "song_title"):
                        song_key = f"{song.artist_name} - {song.song_title}".lower()
                        mainstream_songs.add(song_key)

        # Extract song identifiers from underground platforms
        underground_data = discovery_results.get("underground_platforms", {})
        if "underground_breakdown" in underground_data:
            for platform, songs in underground_data["underground_breakdown"].items():
                for song in songs:
                    if hasattr(song, "artist_name") and hasattr(song, "song_title"):
                        song_key = f"{song.artist_name} - {song.song_title}".lower()
                        underground_songs.add(song_key)

        # Find overlaps
        cross_platform_hits = mainstream_songs.intersection(underground_songs)

        analysis = {
            "total_mainstream_songs": len(mainstream_songs),
            "total_underground_songs": len(underground_songs),
            "cross_platform_hits": len(cross_platform_hits),
            "cross_platform_songs": list(cross_platform_hits),
            "mainstream_only": len(mainstream_songs - underground_songs),
            "underground_only": len(underground_songs - mainstream_songs),
            "cross_platform_percentage": (len(cross_platform_hits) / max(len(mainstream_songs), 1))
            * 100,
        }

        print(f"   📊 {len(cross_platform_hits)} songs found across multiple platforms")

        return analysis

    def _generate_trending_predictions(self, discovery_results: dict[str, Any]) -> dict[str, Any]:
        """Generate predictions for trending music based on discovery patterns."""
        print("\n🔮 Generating Trending Predictions...")

        predictions = {
            "next_viral_candidates": [],
            "breakthrough_artists": [],
            "genre_trends": {},
            "platform_momentum": {},
            "timeline_predictions": {},
        }

        # Analyze viral candidates from underground platforms
        underground_data = discovery_results.get("underground_platforms", {})
        if "underground_breakdown" in underground_data:
            for platform, songs in underground_data["underground_breakdown"].items():
                for song in songs:
                    if hasattr(song, "viral_stage") and hasattr(song, "trend_velocity"):
                        if (
                            song.viral_stage.value in ["emerging", "niche_viral"]
                            and song.trend_velocity > 100
                        ):
                            predictions["next_viral_candidates"].append(
                                {
                                    "artist": song.artist_name,
                                    "song": song.song_title,
                                    "platform": platform,
                                    "momentum": song.trend_velocity,
                                    "prediction": "Likely to go viral in 7-14 days",
                                }
                            )

        # Platform momentum analysis
        mainstream_data = discovery_results.get("mainstream_platforms", {})
        if "platform_discoveries" in mainstream_data:
            for platform, count in mainstream_data["platform_discoveries"].items():
                momentum_score = count / 10  # Normalize
                predictions["platform_momentum"][platform] = {
                    "song_count": count,
                    "momentum_score": momentum_score,
                    "trend": "rising" if momentum_score > 5 else "stable",
                }

        # Timeline predictions
        predictions["timeline_predictions"] = {
            "next_24_hours": "Monitor TikTok and Instagram Reels for viral spikes",
            "next_week": f"{len(predictions['next_viral_candidates'])} songs predicted to gain traction",
            "next_month": "Cross-platform validation expected for current viral content",
        }

        print(f"   🎯 {len(predictions['next_viral_candidates'])} viral candidates identified")

        return predictions

    def _generate_comprehensive_recommendations(
        self, discovery_results: dict[str, Any]
    ) -> list[str]:
        """Generate comprehensive actionable recommendations."""
        recommendations = []

        # Platform-specific recommendations
        mainstream_data = discovery_results.get("mainstream_platforms", {})
        if "platform_discoveries" in mainstream_data:
            platform_counts = mainstream_data["platform_discoveries"]

            # Find dominant platform
            dominant_platform = (
                max(platform_counts.items(), key=lambda x: x[1]) if platform_counts else None
            )
            if dominant_platform:
                recommendations.append(
                    f"{dominant_platform[0].title()} is currently the most active discovery platform "
                    f"({dominant_platform[1]} songs). Prioritize content creation here."
                )

        # Cross-platform recommendations
        cross_platform = discovery_results.get("cross_platform_analysis", {})
        if cross_platform.get("cross_platform_hits", 0) > 3:
            recommendations.append(
                f"Strong cross-platform activity detected ({cross_platform['cross_platform_hits']} hits). "
                "Implement cross-platform promotion campaigns for maximum reach."
            )

        # Underground to mainstream pipeline
        predictions = discovery_results.get("trending_predictions", {})

        if len(predictions.get("next_viral_candidates", [])) > 2:
            recommendations.append(
                f"{len(predictions['next_viral_candidates'])} viral candidates identified on underground platforms. "
                "Consider early partnership or playlist placement opportunities."
            )

        # Timing recommendations
        if discovery_results.get("timestamp"):
            current_hour = datetime.now().hour
            if 18 <= current_hour <= 22:  # Peak Gen Z activity hours
                recommendations.append(
                    "Currently in peak Gen Z engagement hours (6-10 PM). "
                    "Optimal time for content releases and campaign launches."
                )

        # Default recommendations if no specific patterns found
        if not recommendations:
            recommendations.extend(
                [
                    "Continue monitoring across all available platforms for emerging trends",
                    "Focus on TikTok and Instagram Reels for Gen Z audience engagement",
                    "Track Reddit and SoundCloud for early underground trend detection",
                ]
            )

        return recommendations

    def get_discovery_analytics(self, days: int = 7) -> dict[str, Any]:
        """Get analytics on discovery patterns over time."""
        print(f"\n📊 Generating Discovery Analytics (Last {days} days)")

        # This would typically query stored historical data
        # For now, return current state analysis

        analytics = {
            "timeframe": f"Last {days} days",
            "total_discoveries": len(self.discovery_cache),
            "api_status": self.api_manager.get_status_report(),
            "platform_performance": {},
            "trending_velocity": {},
            "discovery_patterns": {},
        }

        # Analyze cached discovery data
        for region, data in self.discovery_cache.items():
            mainstream = data.get("mainstream_platforms", {})
            underground = data.get("underground_platforms", {})

            analytics["platform_performance"][region] = {
                "mainstream_active": len(mainstream.get("platform_discoveries", {})),
                "underground_active": len(underground.get("platform_discoveries", {})),
                "cross_platform_hits": data.get("cross_platform_analysis", {}).get(
                    "cross_platform_hits", 0
                ),
            }

        return analytics

    def save_discovery_report(
        self, discovery_results: dict[str, Any], custom_filename: str | None = None
    ) -> str:
        """Save comprehensive discovery report."""
        output_root = Path("data").resolve()
        if custom_filename:
            candidate = Path(custom_filename)
            if candidate.is_absolute():
                raise ValueError("custom_filename must be a relative path under data/")
            resolved_candidate = (output_root / candidate).resolve()
            if not resolved_candidate.is_relative_to(output_root):
                raise ValueError("custom_filename must not escape the data/ directory")
            filepath = resolved_candidate
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = output_root / f"comprehensive_discovery_report_{timestamp}.json"
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(discovery_results, f, indent=2, default=str, ensure_ascii=False)

        return str(filepath)

    async def run_continuous_monitoring(
        self, interval_hours: int = 4, regions: list[str] | None = None
    ):
        """Run continuous music discovery monitoring."""
        if regions is None:
            regions = ["US", "GB", "CA", "AU"]

        print(f"\n🔄 Starting Continuous Monitoring (Every {interval_hours} hours)")
        print(f"   Regions: {', '.join(regions)}")

        while True:
            try:
                for region in regions:
                    print(f"\n⏰ Running discovery for {region}...")

                    # Check API rate limits
                    api_status = self.api_manager.get_status_report()
                    available_platforms = [
                        platform
                        for platform, status in api_status["platforms"].items()
                        if status["can_make_request"]
                    ]

                    if not available_platforms:
                        print(f"   ⚠️ No APIs available due to rate limits. Skipping {region}")
                        continue

                    # Run discovery
                    results = await self.run_full_discovery(region)

                    # Save results
                    report_path = self.save_discovery_report(results)
                    print(f"   💾 Report saved: {report_path}")

                    # Brief pause between regions
                    await asyncio.sleep(60)

                # Wait for next interval
                print(f"\n😴 Waiting {interval_hours} hours until next discovery run...")
                await asyncio.sleep(interval_hours * 3600)

            except KeyboardInterrupt:
                print("\n🛑 Continuous monitoring stopped by user")
                break
            except Exception as e:
                print(f"\n❌ Error in continuous monitoring: {e}")
                print("   Waiting 30 minutes before retry...")
                await asyncio.sleep(1800)


async def main():
    """Main application entry point."""
    print("🎵 Comprehensive Music Discovery System")
    print("=" * 60)

    # Initialize application
    app = ComprehensiveMusicDiscoveryApp()

    # Check API status
    api_status = app.api_manager.get_status_report()
    enabled_platforms = api_status["summary"]["enabled_platforms"]
    total_platforms = api_status["summary"]["total_platforms"]

    print(f"\n📊 API Status: {enabled_platforms}/{total_platforms} platforms configured")

    if enabled_platforms == 0:
        print("\n⚠️ No API credentials configured!")
        print("Run 'python src/api_config.py' to set up your API keys")
        return

    # Menu system
    while True:
        print("\n🎯 What would you like to do?")
        print("1. Run single discovery scan")
        print("2. View API status")
        print("3. Generate analytics report")
        print("4. Start continuous monitoring")
        print("5. Configure APIs")
        print("6. Exit")

        try:
            choice = input("\nEnter your choice (1-6): ").strip()

            if choice == "1":
                region = input("Enter region code (US, GB, CA, AU) [US]: ").strip() or "US"
                print(f"\n🔍 Running discovery for {region}...")

                results = await app.run_full_discovery(region)

                # Display summary
                mainstream = results.get("mainstream_platforms", {})
                underground = results.get("underground_platforms", {})
                cross_platform = results.get("cross_platform_analysis", {})

                print("\n📊 Discovery Summary:")
                print(f"   Mainstream songs: {mainstream.get('total_songs_discovered', 0)}")
                print(f"   Underground songs: {underground.get('total_underground_songs', 0)}")
                print(f"   Cross-platform hits: {cross_platform.get('cross_platform_hits', 0)}")

                # Save report
                report_path = app.save_discovery_report(results)
                print(f"   💾 Full report saved to: {report_path}")

            elif choice == "2":
                print("\n📊 API Status Report:")
                status = app.api_manager.get_status_report()

                for platform, details in status["platforms"].items():
                    status_icon = "✅" if details["enabled"] else "❌"
                    rate_limit_info = (
                        f"{details['requests_today']}/{details['rate_limits']['per_day']}"
                    )

                    print(f"   {status_icon} {platform.title()}: {rate_limit_info} requests today")

                    if details["error_count"] > 0:
                        print(f"      ⚠️ {details['error_count']} errors")

            elif choice == "3":
                analytics = app.get_discovery_analytics()
                print("\n📈 Analytics Report:")
                print(f"   Total discoveries: {analytics['total_discoveries']}")
                print(f"   Active APIs: {analytics['api_status']['summary']['enabled_platforms']}")

                for region, performance in analytics["platform_performance"].items():
                    print(f"   {region}: {performance['cross_platform_hits']} cross-platform hits")

            elif choice == "4":
                print("\n🔄 Starting Continuous Monitoring...")
                interval = input("Enter monitoring interval in hours [4]: ").strip()
                interval = int(interval) if interval.isdigit() else 4

                regions_input = input("Enter regions (comma-separated) [US,GB,CA,AU]: ").strip()
                regions = (
                    [r.strip() for r in regions_input.split(",")]
                    if regions_input
                    else ["US", "GB", "CA", "AU"]
                )

                await app.run_continuous_monitoring(interval, regions)

            elif choice == "5":
                print("\n🔧 API Configuration...")
                from integrations.api_config import setup_api_credentials

                setup_api_credentials()

                # Reinitialize engines with new credentials
                app._initialize_engines()

            elif choice == "6":
                print("\n👋 Goodbye!")
                break

            else:
                print("Invalid choice. Please enter 1-6.")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    # Run the main application
    asyncio.run(main())
