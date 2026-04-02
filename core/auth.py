"""Spotify authentication module with secure configuration."""

import os
from pathlib import Path

import spotipy
from spotipy.cache_handler import CacheFileHandler
from spotipy.oauth2 import SpotifyOAuth

from .config import get_config


def _resolve_spotify_cache_path() -> Path:
    """Return a private filesystem path for Spotify OAuth tokens."""
    xdg_cache_home = os.getenv("XDG_CACHE_HOME")
    if xdg_cache_home:
        base_dir = Path(xdg_cache_home).expanduser()
    else:
        base_dir = Path.home() / ".cache"
    return base_dir / "audora" / "spotify_oauth.cache"


def get_client() -> spotipy.Spotify:
    """Create an authenticated Spotipy client using secure configuration.

    Uses the SecureConfig class to safely load credentials from environment.

    Returns:
        spotipy.Spotify: Authenticated Spotify client

    Raises:
        ValueError: If required credentials are missing or invalid
    """
    config_manager = get_config()
    spotify_config = config_manager.get_spotify_config()
    cache_path = _resolve_spotify_cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if not cache_path.exists():
        cache_path.touch(mode=0o600, exist_ok=True)
    elif os.name != "nt":
        os.chmod(cache_path, 0o600)

    auth_manager = SpotifyOAuth(
        client_id=spotify_config["client_id"],
        client_secret=spotify_config["client_secret"],
        redirect_uri=spotify_config["redirect_uri"],
        scope=spotify_config["scopes"],
        cache_handler=CacheFileHandler(cache_path=str(cache_path)),
        open_browser=True,
        show_dialog=False,
    )

    return spotipy.Spotify(auth_manager=auth_manager)
