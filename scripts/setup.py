#!/usr/bin/env python3
"""
Enhanced Setup Script for Spotify Music Discovery System v2.0.
Installs dependencies, configures services, and validates the system.
"""

import json
import logging
import platform
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

REQUIREMENTS_FILE = Path(__file__).resolve().parent.parent / "requirements.txt"


class EnhancedMusicDiscoverySetup:
    """Enhanced setup system for the music discovery platform."""

    def __init__(self):
        self.logger = self._setup_logging()
        self.project_root = Path(__file__).parent
        self.config_dir = self.project_root / "config"
        self.data_dir = self.project_root / "data"
        self.logs_dir = self.project_root / "logs"
        self.backups_dir = self.project_root / "backups"
        self.exports_dir = self.project_root / "exports"
        self.templates_dir = self.project_root / "templates"

        # System info
        self.system_info = {
            "platform": platform.system(),
            "python_version": sys.version,
            "architecture": platform.architecture()[0],
        }

    def _setup_logging(self) -> logging.Logger:
        """Set up logging for setup process."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler("setup.log", mode="w"),
            ],
        )
        return logging.getLogger(__name__)

    def run_complete_setup(self) -> bool:
        """Run the complete setup process."""
        self.logger.info("🚀 Starting Enhanced Music Discovery System Setup")
        self.logger.info(
            f"System: {self.system_info['platform']} ({self.system_info['architecture']})"
        )
        self.logger.info(f"Python: {sys.version.split()[0]}")

        setup_steps = [
            ("Creating Directory Structure", self.create_directories),
            ("Installing Python Dependencies", self.install_dependencies),
            ("Setting Up Configuration", self.setup_configuration),
            ("Initializing Database", self.initialize_database),
            ("Creating Templates", self.create_templates),
            ("Setting Up Environment", self.setup_environment),
            ("Validating Installation", self.validate_installation),
            ("Running System Tests", self.run_system_tests),
        ]

        for step_name, step_function in setup_steps:
            try:
                self.logger.info(f"📦 {step_name}...")
                result = step_function()
                if result:
                    self.logger.info(f"✅ {step_name} completed successfully")
                else:
                    self.logger.error(f"❌ {step_name} failed")
                    return False
            except Exception as e:
                self.logger.error(f"❌ {step_name} failed with error: {e}")
                return False

        self.logger.info("🎉 Enhanced Music Discovery System setup completed successfully!")
        self._display_next_steps()
        return True

    def create_directories(self) -> bool:
        """Create all necessary directories."""
        directories = [
            self.config_dir,
            self.data_dir,
            self.data_dir / "trends",
            self.data_dir / "reports",
            self.data_dir / "exports",
            self.data_dir / "visualizations",
            self.logs_dir,
            self.backups_dir,
            self.exports_dir,
            self.templates_dir,
            self.project_root / "plugins",
            self.project_root / "tests",
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"  Created directory: {directory}")
            except Exception as e:
                self.logger.error(f"  Failed to create {directory}: {e}")
                return False

        return True

    def install_dependencies(self) -> bool:
        """Install Python dependencies."""
        self.logger.info("  Installing reviewed package dependencies...")

        # Check if pip is available
        try:
            # Test pip availability
            subprocess.run(  # nosec B603
                [sys.executable, "-m", "pip", "--version"], capture_output=True, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("  pip is not available. Please install pip first.")
            return False

        if not REQUIREMENTS_FILE.exists():
            self.logger.error(f"  Requirements file not found: {REQUIREMENTS_FILE}")
            return False

        try:
            result = subprocess.run(  # nosec B603
                [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
                capture_output=True,
                text=True,
                timeout=900,
            )
        except subprocess.TimeoutExpired:
            self.logger.error("    ❌ Dependency installation timed out")
            return False
        except Exception as e:
            self.logger.error(f"    ❌ Failed to install dependencies: {e}")
            return False

        if result.returncode != 0:
            self.logger.error(f"    ❌ Dependency installation failed: {result.stderr}")
            return False

        self.logger.info("    ✅ Dependencies installed from requirements.txt")
        return True

    def setup_configuration(self) -> bool:
        """Set up configuration files."""
        configs = {
            "enhanced_api_config.json": self._create_enhanced_api_config(),
            "notification_config.json": self._create_notification_config(),
            "analytics_config.json": self._create_analytics_config(),
            "database_config.json": self._create_database_config(),
            "system_config.json": self._create_system_config(),
        }

        for config_file, config_data in configs.items():
            config_path = self.config_dir / config_file
            try:
                with config_path.open("w") as f:
                    json.dump(config_data, f, indent=2)
                self.logger.info(f"  Created config: {config_file}")
            except Exception as e:
                self.logger.error(f"  Failed to create {config_file}: {e}")
                return False

        return True

    def _create_enhanced_api_config(self) -> dict[str, Any]:
        """Create enhanced API configuration."""
        blank = ""
        return {
            "social_media_apis": {
                "tiktok": {
                    "api_key": blank,
                    "api_secret": blank,
                    "access_token": blank,
                    "rate_limit": {"requests_per_minute": 60, "requests_per_hour": 1000},
                    "endpoints": {
                        "trending": "https://api.tiktok.com/v1/trending",
                        "search": "https://api.tiktok.com/v1/search",
                    },
                    "priority": "high",
                },
                "youtube": {
                    "api_key": blank,
                    "rate_limit": {"requests_per_minute": 100, "requests_per_day": 10000},
                    "endpoints": {
                        "trending": "https://www.googleapis.com/youtube/v3/videos",
                        "search": "https://www.googleapis.com/youtube/v3/search",
                    },
                    "priority": "high",
                },
                "twitter": {
                    "bearer_token": blank,
                    "api_key": blank,
                    "api_secret": blank,
                    "access_token": blank,
                    "access_token_secret": blank,
                    "rate_limit": {"requests_per_minute": 300, "requests_per_15min": 450},
                    "priority": "medium",
                },
                "instagram": {
                    "access_token": blank,
                    "client_id": blank,
                    "client_secret": blank,
                    "rate_limit": {"requests_per_hour": 200},
                    "priority": "medium",
                },
                "reddit": {
                    "client_id": blank,
                    "client_secret": blank,
                    "user_agent": "music-discovery-bot/1.0",
                    "rate_limit": {"requests_per_minute": 60},
                    "priority": "low",
                },
                "soundcloud": {
                    "client_id": blank,
                    "rate_limit": {"requests_per_minute": 50},
                    "priority": "low",
                },
            },
            "resilience": {
                "retry_attempts": 3,
                "backoff_factor": 1.5,
                "circuit_breaker_threshold": 5,
                "circuit_breaker_timeout": 300,
            },
            "caching": {"enabled": True, "ttl_seconds": 3600, "max_cache_size": 1000},
        }

    def _create_notification_config(self) -> dict[str, Any]:
        """Create notification configuration."""
        blank = ""
        return {
            "enabled": True,
            "channels": {
                "email": {
                    "enabled": False,
                    "smtp_server": blank,
                    "port": 587,
                    "username": blank,
                    "password": blank,
                    "from_address": "music-discovery@example.com",
                    "recipients": [],
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#music-trends",
                    "username": "Music Discovery Bot",
                },
                "discord": {"enabled": False, "webhook_url": "", "username": "Music Discovery"},
                "webhook": {"enabled": False, "url": "", "headers": {}, "timeout": 30},
                "console": {"enabled": True, "log_level": "INFO"},
            },
            "rules": {
                "viral_prediction_threshold": 0.8,
                "daily_summary_time": "09:00",
                "rate_limit_per_hour": 50,
                "cooldown_minutes": 60,
            },
            "templates": {"use_templates": True, "template_directory": "templates"},
        }

    def _create_analytics_config(self) -> dict[str, Any]:
        """Create analytics configuration."""
        return {
            "machine_learning": {
                "enabled": True,
                "models": {
                    "viral_prediction": {
                        "algorithm": "random_forest",
                        "features": [
                            "growth_rate",
                            "platform_count",
                            "creator_influence",
                            "audio_features",
                        ],
                        "training_data_days": 90,
                    },
                    "trend_clustering": {"algorithm": "dbscan", "min_cluster_size": 5, "eps": 0.3},
                },
            },
            "forecasting": {
                "enabled": True,
                "methods": ["linear_regression", "arima", "moving_average"],
                "forecast_horizon_days": 14,
                "confidence_intervals": True,
            },
            "real_time_analysis": {
                "enabled": True,
                "update_interval_minutes": 15,
                "alert_thresholds": {"sudden_growth": 2.0, "viral_threshold": 0.8},
            },
            "data_quality": {
                "validation_enabled": True,
                "quality_checks": ["missing_data", "outliers", "duplicates"],
                "quality_report_frequency": "daily",
            },
        }

    def _create_database_config(self) -> dict[str, Any]:
        """Create database configuration."""
        return {
            "database": {
                "type": "sqlite",
                "path": "data/enhanced_music_trends.db",
                "backup_enabled": True,
                "backup_frequency": "daily",
                "backup_retention_days": 30,
            },
            "performance": {
                "wal_mode": True,
                "cache_size": 10000,
                "synchronous": "NORMAL",
                "temp_store": "memory",
            },
            "indexes": {"auto_create": True, "optimization_enabled": True},
            "maintenance": {"vacuum_frequency": "weekly", "analyze_frequency": "daily"},
        }

    def _create_system_config(self) -> dict[str, Any]:
        """Create system configuration."""
        return {
            "system": {
                "name": "Enhanced Music Discovery System",
                "version": "2.0.0",
                "environment": "development",
            },
            "logging": {
                "level": "INFO",
                "file_logging": True,
                "log_rotation": True,
                "max_log_size_mb": 100,
                "backup_count": 5,
            },
            "monitoring": {
                "health_checks": True,
                "performance_metrics": True,
                "uptime_monitoring": True,
            },
            "security": {"api_key_rotation": True, "secure_storage": True, "audit_logging": True},
            "features": {
                "web_dashboard": True,
                "api_endpoints": True,
                "plugin_system": True,
                "notification_system": True,
            },
        }

    def initialize_database(self) -> bool:
        """Initialize the enhanced database."""
        try:
            # Import and initialize the enhanced data store
            sys.path.append(str(self.project_root / "src"))
            from data_store import EnhancedMusicDataStore

            db_path = self.data_dir / "enhanced_music_trends.db"
            data_store = EnhancedMusicDataStore(str(db_path))

            self.logger.info(f"  Database initialized at: {db_path}")

            # Create initial backup
            backup_path = data_store.create_backup()
            self.logger.info(f"  Initial backup created: {backup_path}")

            return True

        except Exception as e:
            self.logger.error(f"  Database initialization failed: {e}")
            return False

    def create_templates(self) -> bool:
        """Create notification templates."""
        templates = {
            "viral_prediction.txt": """
🔥 VIRAL PREDICTION ALERT 🔥

Track: {{ track_name }} by {{ artist }}
Viral Probability: {{ viral_probability }}%
Confidence: {{ confidence }}%
Predicted Peak: {{ predicted_peak_date }}

Key Factors:
{% for factor in key_factors %}
• {{ factor }}
{% endfor %}

{% if risk_factors %}
Risk Factors:
{% for risk in risk_factors %}
⚠️ {{ risk }}
{% endfor %}
{% endif %}

This track is likely to break mainstream soon!
""",
            "daily_summary.txt": """
📈 Daily Music Trends - {{ date }}

Top {{ track_count }} trending tracks:

{% for track in tracks %}
{{ loop.index }}. {{ track.track_name }} by {{ track.artist }}
   Platform: {{ track.platform }} | Score: {{ track.score }}
   {% if track.growth_rate %}Growth: {{ track.growth_rate }}x{% endif %}

{% endfor %}

Cross-platform hits: {{ cross_platform_count }}
New discoveries: {{ new_discoveries }}

Stay ahead of the trends!
""",
            "system_alert.txt": """
⚠️ SYSTEM ALERT: {{ alert_type }}

Issue: {{ issue_description }}
Severity: {{ severity }}
Timestamp: {{ timestamp }}

{% if affected_components %}
Affected Components:
{% for component in affected_components %}
• {{ component }}
{% endfor %}
{% endif %}

{% if resolution_steps %}
Recommended Actions:
{% for step in resolution_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

System Status: {{ system_status }}
""",
        }

        for template_name, template_content in templates.items():
            template_path = self.templates_dir / template_name
            try:
                with template_path.open("w") as f:
                    f.write(template_content.strip())
                self.logger.info(f"  Created template: {template_name}")
            except Exception as e:
                self.logger.error(f"  Failed to create template {template_name}: {e}")
                return False

        return True

    def setup_environment(self) -> bool:
        """Set up environment variables."""
        env_template = """
# Enhanced Music Discovery System Environment Configuration

# Database
DATABASE_PATH=data/enhanced_music_trends.db

# API Keys (Fill in your actual keys)
TIKTOK_API_KEY=your_tiktok_api_key_here
YOUTUBE_API_KEY=your_youtube_api_key_here
TWITTER_BEARER_TOKEN=your_twitter_bearer_token_here
INSTAGRAM_ACCESS_TOKEN=your_instagram_access_token_here
REDDIT_CLIENT_ID=your_reddit_client_id_here
REDDIT_CLIENT_SECRET=your_reddit_client_secret_here

# Notification Services
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_RECIPIENTS=notifications@yourdomain.com

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK/URL

# System Configuration
LOG_LEVEL=INFO
ENVIRONMENT=development
DEBUG=False

# Feature Flags
ENABLE_WEB_DASHBOARD=True
ENABLE_REAL_TIME_ANALYSIS=True
ENABLE_ML_PREDICTIONS=True
ENABLE_NOTIFICATIONS=True
"""

        env_path = self.project_root / ".env.enhanced"
        try:
            with env_path.open("w") as f:
                f.write(env_template.strip())
            self.logger.info(f"  Created environment file: {env_path}")
            self.logger.info("  ⚠️ Remember to update .env.enhanced with your actual API keys!")
            return True
        except Exception as e:
            self.logger.error(f"  Failed to create .env file: {e}")
            return False

    def validate_installation(self) -> bool:
        """Validate the installation."""
        self.logger.info("  Validating installation components...")

        validation_checks = [
            ("Directory structure", self._validate_directories),
            ("Configuration files", self._validate_configs),
            ("Python dependencies", self._validate_dependencies),
            ("Database connection", self._validate_database),
            ("Core modules", self._validate_modules),
        ]

        all_passed = True
        for check_name, check_function in validation_checks:
            try:
                result = check_function()
                if result:
                    self.logger.info(f"    ✅ {check_name}: PASSED")
                else:
                    self.logger.error(f"    ❌ {check_name}: FAILED")
                    all_passed = False
            except Exception as e:
                self.logger.error(f"    ❌ {check_name}: ERROR - {e}")
                all_passed = False

        return all_passed

    def _validate_directories(self) -> bool:
        """Validate directory structure."""
        required_dirs = [
            self.config_dir,
            self.data_dir,
            self.logs_dir,
            self.backups_dir,
            self.templates_dir,
        ]
        return all(d.exists() for d in required_dirs)

    def _validate_configs(self) -> bool:
        """Validate configuration files."""
        required_configs = [
            "enhanced_api_config.json",
            "notification_config.json",
            "analytics_config.json",
            "database_config.json",
        ]
        return all((self.config_dir / config).exists() for config in required_configs)

    def _validate_dependencies(self) -> bool:
        """Validate Python dependencies."""
        critical_packages = ["pandas", "numpy", "sklearn", "aiohttp", "jinja2"]

        for package in critical_packages:
            try:
                __import__(package)
            except ImportError:
                self.logger.error(f"    Missing critical package: {package}")
                return False
        return True

    def _validate_database(self) -> bool:
        """Validate database connectivity."""
        try:
            sys.path.append(str(self.project_root / "src"))
            from data_store import EnhancedMusicDataStore

            db_path = self.data_dir / "enhanced_music_trends.db"
            data_store = EnhancedMusicDataStore(str(db_path))

            # Test basic database operations
            quality_report = data_store.get_data_quality_report()
            return isinstance(quality_report, dict)

        except Exception as e:
            self.logger.error(f"    Database validation error: {e}")
            return False

    def _validate_modules(self) -> bool:
        """Validate core modules can be imported."""
        try:
            sys.path.append(str(self.project_root / "src"))

            # Test imports
            __import__("resilience")
            __import__("data_store")
            __import__("advanced_analytics")

            return True

        except Exception as e:
            self.logger.error(f"    Module validation error: {e}")
            return False

    def run_system_tests(self) -> bool:
        """Run basic system tests."""
        self.logger.info("  Running system tests...")

        try:
            sys.path.append(str(self.project_root / "src"))

            # Test 1: Resilience system
            from resilience import EnhancedResilience

            resilience = EnhancedResilience()
            resilience.health_check()  # Test health check
            self.logger.info("    ✅ Resilience system: OK")

            # Test 2: Data store
            from data_store import EnhancedMusicDataStore

            data_store = EnhancedMusicDataStore(":memory:")  # In-memory for testing
            data_store.get_data_quality_report()  # Test database operations
            self.logger.info("    ✅ Data store: OK")

            # Test 3: Analytics engine
            from advanced_analytics import MusicTrendAnalytics

            MusicTrendAnalytics()  # Test initialization
            self.logger.info("    ✅ Analytics engine: OK")

            return True

        except Exception as e:
            self.logger.error(f"    System test failed: {e}")
            return False

    def _display_next_steps(self) -> None:
        """Display next steps for the user."""
        print("\n" + "=" * 80)
        print("🎉 ENHANCED MUSIC DISCOVERY SYSTEM SETUP COMPLETE! 🎉".center(80))
        print("=" * 80)

        print("\n📋 NEXT STEPS:")
        print("\n1. 🔑 Configure API Keys:")
        print("   • Edit the .env.enhanced file with your actual API credentials")
        print("   • Most important: YouTube API, TikTok API, Twitter API")
        print("   • Free tier available for most platforms")

        print("\n2. 🧪 Test the System:")
        print("   • Run: python src/music_discovery_app.py")
        print("   • Or test individual components:")
        print("     - python src/resilience.py")
        print("     - python src/data_store.py")
        print("     - python src/advanced_analytics.py")

        print("\n3. 📱 Set Up Notifications:")
        print("   • Configure Slack/Discord webhooks in config/notification_config.json")
        print("   • Set up email SMTP settings in .env.enhanced")
        print("   • Test with: python src/notification_service.py")

        print("\n4. 🎯 Start Music Discovery:")
        print("   • Configure APIs: python src/api_config.py")
        print("   • Run discovery: python src/music_discovery_app.py")
        print("   • Monitor trends with the dashboard")

        print("\n5. 📊 Advanced Features:")
        print("   • Enable machine learning predictions")
        print("   • Set up automated monitoring")
        print("   • Create custom notification rules")
        print("   • Explore the plugin system")

        print("\n💡 DOCUMENTATION:")
        print("   • Full guide: MUSIC_DISCOVERY_README.md")
        print("   • Quick start: QUICK_START.md")
        print("   • Implementation details: IMPLEMENTATION_SUMMARY.md")

        print("\n🆘 NEED HELP?")
        print("   • Check the logs in logs/ directory")
        print("   • Review configuration files in config/")
        print("   • Run setup again if needed: python enhanced_setup.py")

        print("\n" + "=" * 80)
        print("Ready to discover the next viral hit! 🎵🚀".center(80))
        print("=" * 80 + "\n")


def main():
    """Main setup function."""
    setup = EnhancedMusicDiscoverySetup()

    try:
        success = setup.run_complete_setup()
        if success:
            print("\n✅ Setup completed successfully!")
            return 0
        else:
            print("\n❌ Setup failed. Check setup.log for details.")
            return 1
    except KeyboardInterrupt:
        print("\n⚠️ Setup interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        logging.error(f"Unexpected error during setup: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
