"""Spotify authentication module with secure configuration."""

import os

import spotipy
from spotipy.cache_handler import CacheFileHandler
from spotipy.oauth2 import SpotifyOAuth

from .config import get_config
from .utils import PROJECT_ROOT


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
    cache_path = PROJECT_ROOT / ".cache"
    if cache_path.is_symlink():
        raise ValueError("Spotify token cache cannot be a symlink")
    if not cache_path.exists():
        cache_path.touch(mode=0o600, exist_ok=True)
    elif os.name != "nt":
        cache_path.chmod(0o600)

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
