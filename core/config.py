"""Secure configuration management for API keys and secrets."""

import os
import sys
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv


class SecureConfig:
    """Secure configuration manager with validation and error handling."""

    def __init__(self, env_file: str | None = None):
        """Initialize secure config manager.

        Args:
            env_file: Path to .env file. If None, searches for .env in project root.
        """
        self.project_root = Path(__file__).resolve().parent.parent
        self.env_file = Path(env_file) if env_file else self.project_root / ".env"
        self._config: dict[str, Any] = {}
        self._load_environment()

    def _load_environment(self):
        """Load environment variables securely."""
        if not self.env_file.exists():
            warnings.warn(
                f"Environment file not found: {self.env_file}\n"
                "Create a .env file with your API credentials.",
                UserWarning,
                stacklevel=2,
            )
            return

        # Load with explicit encoding and override
        load_dotenv(dotenv_path=str(self.env_file), override=True, encoding="utf-8")

        # Validate file permissions (Unix-like systems)
        if hasattr(os, "stat") and not sys.platform.startswith("win"):
            file_mode = oct(self.env_file.stat().st_mode)[-3:]
            if file_mode != "600":
                warnings.warn(
                    f"Environment file permissions are too open: {file_mode}\n"
                    f"Consider running: chmod 600 {self.env_file}",
                    UserWarning,
                    stacklevel=2,
                )

    def get_spotify_config(self) -> dict[str, str]:
        """Get Spotify API configuration with validation."""
        config = {
            "client_id": self._get_required_env("SPOTIFY_CLIENT_ID"),
            "client_secret": self._get_required_env("SPOTIFY_CLIENT_SECRET"),
            "redirect_uri": self._get_required_env("SPOTIFY_REDIRECT_URI"),
            "scopes": os.getenv(
                "SPOTIFY_SCOPES", "user-top-read user-read-recently-played playlist-read-private"
            ),
        }

        # Validate redirect URI format
        parsed_redirect = urlparse(config["redirect_uri"])
        allowed_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed_redirect.scheme != "http" or parsed_redirect.hostname not in allowed_hosts:
            raise ValueError(
                f"Invalid redirect URI: {config['redirect_uri']}\n"
                "For development, use http://localhost, http://127.0.0.1, or http://[::1]"
            )

        return config

    def get_lastfm_config(self) -> dict[str, str] | None:
        """Get Last.fm API configuration with validation."""
        api_key = os.getenv("LASTFM_API_KEY")
        shared_secret = os.getenv("LASTFM_SHARED_SECRET")

        if not api_key or api_key in ("your_lastfm_api_key_here", ""):
            return None

        # Validate API key format (Last.fm keys are 32 char hex)
        if not self._is_valid_lastfm_key(api_key):
            warnings.warn(
                "Last.fm API key format appears invalid. "
                "Should be 32 character hexadecimal string.",
                UserWarning,
                stacklevel=2,
            )

        return {"api_key": api_key, "shared_secret": shared_secret or ""}

    def _get_required_env(self, key: str) -> str:
        """Get required environment variable with validation."""
        value = os.getenv(key)

        if not value or value in (f"your_{key.lower()}_here", ""):
            raise ValueError(
                f"Missing required environment variable: {key}\n"
                f"Add {key}=your_actual_value to your .env file"
            )

        return value

    def get_audiodb_config(self) -> dict[str, str] | None:
        """Get AudioDB API configuration with validation."""
        api_key = os.getenv("AUDIODB_API_KEY")

        # AudioDB provides a free API key (123) that everyone can use
        # Premium keys are longer alphanumeric strings
        if not api_key or api_key in ("your_audiodb_api_key_here", ""):
            return {"api_key": "123", "tier": "free"}  # Free API key

        # Validate premium key format (should be longer than the free key)
        if len(api_key) > 5:  # Premium keys are longer
            return {"api_key": api_key, "tier": "premium"}

        return {"api_key": "123", "tier": "free"}  # Default to free

    def _is_valid_lastfm_key(self, key: str) -> bool:
        """Validate Last.fm API key format."""
        return len(key) == 32 and all(c in "0123456789abcdef" for c in key.lower())

    def validate_all_configs(self) -> dict[str, dict[str, Any]]:
        """Validate all configurations and return status."""
        status: dict[str, dict[str, Any]] = {
            "spotify": {"configured": False, "error": None},
            "lastfm": {"configured": False, "error": None},
            "audiodb": {"configured": False, "error": None},
        }

        # Test Spotify config
        try:
            spotify_config = self.get_spotify_config()
            status["spotify"]["configured"] = True
            status["spotify"]["scopes"] = spotify_config["scopes"].split()
        except (ValueError, KeyError, OSError) as e:
            status["spotify"]["error"] = str(e)

        # Test Last.fm config
        try:
            lastfm_config = self.get_lastfm_config()
            if lastfm_config:
                status["lastfm"]["configured"] = True
            else:
                status["lastfm"]["error"] = "API key not configured"
        except (ValueError, KeyError, OSError) as e:
            status["lastfm"]["error"] = str(e)

        # Test AudioDB config
        try:
            audiodb_config = self.get_audiodb_config()
            if audiodb_config:
                status["audiodb"]["configured"] = True
                status["audiodb"]["tier"] = audiodb_config["tier"]
            else:
                status["audiodb"]["error"] = "API configuration failed"
        except (ValueError, KeyError, OSError) as e:
            status["audiodb"]["error"] = str(e)

        return status

    def create_env_template(self) -> str:
        """Create a template .env file content."""
        template = """# Spotify API Configuration
# Get these from: https://developer.spotify.com/dashboard
SPOTIFY_CLIENT_ID=your_spotify_client_id_here
SPOTIFY_CLIENT_SECRET=your_spotify_client_secret_here
SPOTIFY_REDIRECT_URI=http://127.0.0.1:8888/callback
SPOTIFY_SCOPES=user-top-read user-read-recently-played playlist-read-private user-library-read

# Last.fm API Configuration (Optional)
# Get these from: https://www.last.fm/api/account/create
LASTFM_API_KEY=your_lastfm_api_key_here
LASTFM_SHARED_SECRET=your_lastfm_shared_secret_here

# AudioDB API Configuration (Optional - defaults to free tier)
# Get premium key from: https://www.theaudiodb.com/ (after creating account)
# Free tier (123) provides basic access, premium unlocks additional features
AUDIODB_API_KEY=123

# Security Notes:
# - Never commit this file to version control
# - Keep file permissions restrictive (chmod 600 on Unix systems)
# - Regenerate keys if they are ever exposed
"""
        return template

    def setup_interactive(self):
        """Interactive setup for first-time users."""
        print("🔐 Spotify Insights - Secure Configuration Setup")
        print("=" * 50)

        if self.env_file.exists():
            print(f"✅ Found existing .env file: {self.env_file}")
            status = self.validate_all_configs()

            if status["spotify"]["configured"]:
                print("✅ Spotify API: Configured")
            else:
                print(f"❌ Spotify API: {status['spotify']['error']}")

            if status["lastfm"]["configured"]:
                print("✅ Last.fm API: Configured")
            else:
                print(f"⚠️  Last.fm API: {status['lastfm']['error']}")
        else:
            print(f"❌ No .env file found at: {self.env_file}")
            print("\n📝 Creating template .env file...")

            self.env_file.write_text(self.create_env_template(), encoding="utf-8")

            # Set restrictive permissions on Unix-like systems
            if hasattr(os, "chmod") and not sys.platform.startswith("win"):
                self.env_file.chmod(0o600)

            print(f"✅ Created template: {self.env_file}")
            print("\n🔑 Next steps:")
            print("1. Open the .env file and add your API credentials")
            print("2. Get Spotify credentials: https://developer.spotify.com/dashboard")
            print("3. Get Last.fm credentials: https://www.last.fm/api/account/create")
            print("4. Run this script again to validate")


# Global config instance
_config_instance = None


def get_config() -> SecureConfig:
    """Get global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = SecureConfig()
    return _config_instance


def validate_environment() -> bool:
    """Quick validation check for all required environment variables."""
    config = get_config()
    status = config.validate_all_configs()

    spotify_ok = status["spotify"]["configured"]
    lastfm_ok = status["lastfm"]["configured"]

    if not spotify_ok:
        print(f"❌ Spotify configuration error: {status['spotify']['error']}")
        return False

    if not lastfm_ok:
        print(f"⚠️  Last.fm not configured: {status['lastfm']['error']}")
        print("   Last.fm features will be disabled.")

    return True


if __name__ == "__main__":
    # Interactive setup when run directly
    config = SecureConfig()
    config.setup_interactive()
