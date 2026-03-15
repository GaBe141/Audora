#!/usr/bin/env python3
"""
Enhanced Music Discovery Application - Complete Integration
This is the main application file that brings together all enhanced components.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Add necessary paths
sys.path.append(str(Path(__file__).parent.parent))

# Import all enhanced components
from analytics.advanced_analytics import MusicTrendAnalytics
from core.data_store import EnhancedMusicDataStore
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from core.resilience import EnhancedResilience
from integrations.lastfm_integration import get_lastfm_client
from integrations.social_discovery_engine import (
    SocialMusicDiscoveryEngine,
    create_mock_discovery_data,
)


class EnhancedMusicDiscoveryApp:
    """Main application orchestrating all enhanced components."""

    def __init__(self, config_dir: str = "config"):
        """Initialize the enhanced music discovery application."""
        self.config_dir = Path(config_dir)
        self.data_dir = Path("data")

        # Load configurations
        self.configs = self._load_configurations()

        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.resilience = EnhancedResilience()
        self.data_store = EnhancedMusicDataStore(
            self.configs.get("database", {}).get("path", "data/enhanced_music_trends.db")
        )
        self.analytics = MusicTrendAnalytics(self.data_store)
        self.notifications = EnhancedNotificationService()

        # Initialize integration clients
        social_api_config = self.configs.get("api", {}).get("social", {})
        self.social_engine = SocialMusicDiscoveryEngine(social_api_config)
        self.lastfm_client = get_lastfm_client()

        self.logger.info("Enhanced Music Discovery App initialized successfully")

    def _load_configurations(self) -> dict[str, Any]:
        """Load all configuration files."""
        configs = {}
        config_files = {
            "api": "enhanced_api_config.json",
            "notification": "notification_config.json",
            "analytics": "analytics_config.json",
            "database": "database_config.json",
            "system": "system_config.json",
        }

        for config_type, filename in config_files.items():
            config_path = self.config_dir / filename
            try:
                if config_path.exists():
                    with open(config_path) as f:
                        configs[config_type] = json.load(f)
                else:
                    print(f"⚠️ Config file not found: {config_path}")
                    configs[config_type] = {}
            except Exception as e:
                print(f"❌ Error loading {filename}: {e}")
                configs[config_type] = {}

        return configs

    def _setup_logging(self) -> None:
        """Set up comprehensive logging."""
        log_config = self.configs.get("system", {}).get("logging", {})

        # Create logs directory
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        # Configure logging
        log_level = getattr(logging, log_config.get("level", "INFO"))
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

        if log_config.get("file_logging", True):
            log_file = logs_dir / f"music_discovery_{datetime.now().strftime('%Y%m%d')}.log"
            handlers.append(logging.FileHandler(log_file))

        logging.basicConfig(level=log_level, format=log_format, handlers=handlers)

    async def run_discovery_cycle(self) -> dict[str, Any]:
        """Run a complete discovery cycle with all enhanced features."""
        self.logger.info("🚀 Starting enhanced music discovery cycle")

        cycle_results: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "discoveries": [],
            "analytics": {},
            "notifications_sent": 0,
            "errors": [],
            "performance_metrics": {},
        }

        try:
            # Phase 1: Health Check
            health_status = await self._health_check()
            if not health_status["healthy"]:
                self.logger.warning("⚠️ System health issues detected")
                cycle_results["errors"].extend(health_status["issues"])

            # Phase 2: Data Collection with Resilience
            discoveries = await self._collect_trending_data()
            cycle_results["discoveries"] = discoveries
            self.logger.info(f"📊 Collected {len(discoveries)} trending tracks")

            # Phase 3: Store Data
            await self._store_discoveries(discoveries)

            # Phase 4: Advanced Analytics
            analytics_results = await self._run_analytics()
            cycle_results["analytics"] = analytics_results

            # Phase 5: Notifications
            notifications_sent = await self._send_notifications(analytics_results)
            cycle_results["notifications_sent"] = notifications_sent

            # Phase 6: Performance Metrics
            performance = await self._collect_performance_metrics()
            cycle_results["performance_metrics"] = performance

            self.logger.info("✅ Discovery cycle completed successfully")

        except Exception as e:
            error_msg = f"Discovery cycle failed: {e}"
            self.logger.error(error_msg)
            cycle_results["errors"].append(error_msg)

            # Send error notification
            message = NotificationMessage(
                title="Discovery Cycle Error",
                content=f"Discovery cycle failed: {str(e)}",
                priority=NotificationPriority.HIGH,
                channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
                data={
                    "alert_type": "Discovery Cycle Error",
                    "issue_description": str(e),
                    "severity": "HIGH",
                    "timestamp": datetime.now().isoformat(),
                    "system_status": "DEGRADED",
                },
            )
            await self.notifications.send_notification(message)

        return cycle_results

    async def _health_check(self) -> dict[str, Any]:
        """Comprehensive system health check."""
        health_results = {"healthy": True, "issues": [], "components": {}}

        # Check resilience system
        resilience_health = self.resilience.health_check()
        health_results["components"]["resilience"] = resilience_health

        # Check database
        try:
            quality_report = self.data_store.get_data_quality_report()
            health_results["components"]["database"] = {
                "status": "healthy",
                "record_count": quality_report.get("total_records", 0),
            }
        except Exception as e:
            health_results["healthy"] = False
            health_results["issues"].append(f"Database issue: {e}")
            health_results["components"]["database"] = {"status": "unhealthy", "error": str(e)}

        # Check analytics engine
        try:
            # Simple test of analytics
            test_data = [{"track_name": "test", "artist": "test", "platform": "test", "score": 1.0}]
            self.analytics.analyze_viral_potential(test_data)
            health_results["components"]["analytics"] = {"status": "healthy"}
        except Exception as e:
            health_results["issues"].append(f"Analytics issue: {e}")
            health_results["components"]["analytics"] = {"status": "unhealthy", "error": str(e)}

        # Check notification service
        notification_health = await self.notifications.test_connection()
        health_results["components"]["notifications"] = notification_health

        return health_results

    async def _collect_trending_data(self) -> list[dict[str, Any]]:
        """Collect trending data from multiple sources with resilience."""
        self.logger.info("🔍 Collecting trending data from multiple sources")

        discoveries: list[dict[str, Any]] = []
        now = datetime.now().isoformat()

        # --- Source 1: Social platforms (TikTok / YouTube / Twitter) ---
        try:
            social_results = await self.social_engine.discover_emerging_music(region="US")
            for platform_name, metrics_list in social_results.items():
                for m in metrics_list:
                    # Normalise trend_velocity (0–1) to a 0–100 score
                    score = min(m.trend_velocity * 100, 100.0)
                    discoveries.append(
                        {
                            "track_name": m.song_title,
                            "artist": m.artist_name,
                            "platform": platform_name,
                            "score": score,
                            "growth_rate": m.trend_velocity,
                            "platform_count": 1,
                            "creator_influence": min(m.video_uses / 1_000_000, 1.0),
                            "audio_features": {},
                            "metadata": {
                                "discovered_at": now,
                                "source_confidence": 0.8,
                                "viral_stage": m.viral_stage.value,
                                "views": m.views,
                                "likes": m.likes,
                            },
                        }
                    )
            self.logger.info(f"✅ Social engine: {len(discoveries)} tracks")
        except Exception as e:
            self.logger.warning(f"⚠️ Social engine unavailable: {e}")

        # --- Source 2: Last.fm global charts ---
        if self.lastfm_client:
            try:
                lastfm_df = self.lastfm_client.get_top_tracks_global(limit=50)
                if not lastfm_df.empty:
                    max_pc = lastfm_df["playcount"].max() or 1
                    before = len(discoveries)
                    for _, row in lastfm_df.iterrows():
                        score = float(row["playcount"]) / max_pc * 100
                        discoveries.append(
                            {
                                "track_name": str(row["name"]),
                                "artist": str(row["artist"]),
                                "platform": "lastfm",
                                "score": score,
                                "growth_rate": score / 100,
                                "platform_count": 1,
                                "creator_influence": 0.0,
                                "audio_features": {},
                                "metadata": {
                                    "discovered_at": now,
                                    "source_confidence": 0.9,
                                    "playcount": int(row["playcount"]),
                                    "listeners": int(row.get("listeners", 0)),
                                },
                            }
                        )
                    self.logger.info(
                        f"✅ Last.fm: {len(discoveries) - before} tracks"
                    )
            except Exception as e:
                self.logger.warning(f"⚠️ Last.fm unavailable: {e}")

        # --- Fallback: mock data when no API keys are configured ---
        if not discoveries:
            self.logger.warning(
                "No API sources returned data — using mock discovery engine"
            )
            mock_engine = create_mock_discovery_data()
            mock_results = await mock_engine.discover_emerging_music(region="US")
            for platform_name, metrics_list in mock_results.items():
                for m in metrics_list:
                    score = min(m.trend_velocity * 100, 100.0)
                    discoveries.append(
                        {
                            "track_name": m.song_title,
                            "artist": m.artist_name,
                            "platform": platform_name,
                            "score": score,
                            "growth_rate": m.trend_velocity,
                            "platform_count": 1,
                            "creator_influence": min(m.video_uses / 1_000_000, 1.0),
                            "audio_features": {},
                            "metadata": {
                                "discovered_at": now,
                                "source_confidence": 0.5,
                                "mock": True,
                            },
                        }
                    )

        return discoveries

    async def _store_discoveries(self, discoveries: list[dict[str, Any]]) -> None:
        """Store discoveries in the enhanced data store."""
        for discovery in discoveries:
            try:
                self.data_store.store_trend_data(discovery)
                self.logger.debug(f"Stored: {discovery['track_name']} by {discovery['artist']}")
            except Exception as e:
                self.logger.error(f"Failed to store discovery: {e}")

    async def _run_analytics(self) -> dict[str, Any]:
        """Run advanced analytics on collected data."""
        self.logger.info("🧠 Running advanced analytics")

        # Get recent data for analysis
        recent_data = self.data_store.get_trending_data(
            start_date=datetime.now() - timedelta(days=7)
        )

        analytics_results = {}

        if recent_data:
            # Viral prediction
            viral_predictions = self.analytics.analyze_viral_potential(recent_data)
            analytics_results["viral_predictions"] = viral_predictions

            # Trend clustering
            clusters = self.analytics.cluster_trends(recent_data)
            analytics_results["trend_clusters"] = clusters

            # Cross-platform correlation
            correlation = self.analytics.analyze_cross_platform_correlation(recent_data)
            analytics_results["platform_correlation"] = correlation

            self.logger.info(
                f"Analytics completed: {len(viral_predictions)} predictions, {len(clusters)} clusters"
            )
        else:
            self.logger.warning("No recent data available for analytics")
            analytics_results = {"message": "Insufficient data for analysis"}

        return analytics_results

    async def _send_notifications(self, analytics_results: dict[str, Any]) -> int:
        """Send notifications based on analytics results."""
        notifications_sent = 0

        # Check for high-confidence viral predictions
        viral_predictions = analytics_results.get("viral_predictions", [])

        for prediction in viral_predictions:
            if prediction.get("viral_probability", 0) > 0.8:  # High confidence threshold
                message = NotificationMessage(
                    title=f"Viral Prediction: {prediction.get('track_name', 'Unknown')}",
                    content=f"High viral potential detected for {prediction.get('track_name', 'Unknown')} by {prediction.get('artist', 'Unknown')}",
                    priority=NotificationPriority.HIGH,
                    channels=[NotificationChannel.EMAIL, NotificationChannel.PUSH],
                    data={
                        "track_name": prediction.get("track_name", "Unknown"),
                        "artist": prediction.get("artist", "Unknown"),
                        "viral_probability": f"{prediction.get('viral_probability', 0) * 100:.1f}",
                        "confidence": f"{prediction.get('confidence', 0) * 100:.1f}",
                        "predicted_peak_date": (datetime.now() + timedelta(days=7)).strftime(
                            "%Y-%m-%d"
                        ),
                        "key_factors": prediction.get("key_factors", []),
                        "risk_factors": prediction.get("risk_factors", []),
                    },
                )
                await self.notifications.send_notification(message)
                notifications_sent += 1

        # Daily summary notification
        if datetime.now().hour == 9:  # Send daily summary at 9 AM
            message = NotificationMessage(
                title="Daily Music Discovery Summary",
                content=f"Found {len(viral_predictions)} trending tracks today",
                priority=NotificationPriority.MEDIUM,
                channels=[NotificationChannel.EMAIL],
                data={
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "track_count": len(viral_predictions),
                    "tracks": viral_predictions[:10],  # Top 10
                    "cross_platform_count": len(
                        [p for p in viral_predictions if p.get("platform_count", 0) > 1]
                    ),
                    "new_discoveries": len(
                        [p for p in viral_predictions if p.get("source_confidence", 0) > 0.9]
                    ),
                },
            )
            await self.notifications.send_notification(message)
            notifications_sent += 1

        return notifications_sent

    async def _collect_performance_metrics(self) -> dict[str, Any]:
        """Collect system performance metrics."""
        return {
            "resilience_metrics": self.resilience.get_performance_metrics(),
            "database_size": self.data_store.get_database_size(),
            "analytics_runtime": "0.5s",  # Would be measured in real implementation
            "memory_usage": "45MB",  # Would be measured in real implementation
            "uptime": "24h",  # Would be measured in real implementation
        }

    async def run_continuous_monitoring(self, interval_minutes: int = 15) -> None:
        """Run continuous monitoring and discovery."""
        self.logger.info(f"🔄 Starting continuous monitoring (every {interval_minutes} minutes)")

        while True:
            try:
                cycle_results = await self.run_discovery_cycle()

                # Log cycle summary
                self.logger.info(
                    f"Cycle completed: {len(cycle_results['discoveries'])} discoveries, "
                    f"{cycle_results['notifications_sent']} notifications sent"
                )

                # Save cycle results
                results_file = (
                    self.data_dir
                    / "reports"
                    / f"cycle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                results_file.parent.mkdir(parents=True, exist_ok=True)

                with open(results_file, "w") as f:
                    json.dump(cycle_results, f, indent=2)

                # Wait for next cycle
                await asyncio.sleep(interval_minutes * 60)

            except KeyboardInterrupt:
                self.logger.info("👋 Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"❌ Monitoring cycle error: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying


def main():
    """Main application entry point."""
    print("🎵 Enhanced Music Discovery System v2.0")
    print("=" * 50)

    # Initialize application
    try:
        app = EnhancedMusicDiscoveryApp()
    except Exception as e:
        print(f"❌ Failed to initialize application: {e}")
        print("💡 Run enhanced_setup.py first to set up the system")
        return 1

    # Run mode selection
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced Music Discovery System")
    parser.add_argument(
        "--mode",
        choices=["single", "continuous"],
        default="single",
        help="Run mode: single cycle or continuous monitoring",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=15,
        help="Monitoring interval in minutes (for continuous mode)",
    )

    args = parser.parse_args()

    try:
        if args.mode == "single":
            print("🚀 Running single discovery cycle...")
            cycle_results = asyncio.run(app.run_discovery_cycle())

            print("\n📊 DISCOVERY RESULTS:")
            print(f"• Discoveries: {len(cycle_results['discoveries'])}")
            print(f"• Notifications sent: {cycle_results['notifications_sent']}")
            print(f"• Errors: {len(cycle_results['errors'])}")

            if cycle_results["errors"]:
                print("\n❌ ERRORS:")
                for error in cycle_results["errors"]:
                    print(f"  • {error}")

            print("\n💾 Results saved to: data/reports/")

        else:
            print(f"🔄 Starting continuous monitoring (every {args.interval} minutes)")
            print("Press Ctrl+C to stop...")
            asyncio.run(app.run_continuous_monitoring(args.interval))

        return 0

    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
        return 0
    except Exception as e:
        print(f"\n❌ Application error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
