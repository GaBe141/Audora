"""Spotify authentication module with secure configuration."""

import spotipy
from spotipy.oauth2 import SpotifyOAuth

from core.utils import PROJECT_ROOT, JsonTokenCache

from .config import get_config


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
    auth_manager = SpotifyOAuth(
        client_id=spotify_config["client_id"],
        client_secret=spotify_config["client_secret"],
        redirect_uri=spotify_config["redirect_uri"],
        scope=spotify_config["scopes"],
        cache_handler=JsonTokenCache(PROJECT_ROOT / ".cache"),
        open_browser=True,
        show_dialog=False,
    )

    return spotipy.Spotify(auth_manager=auth_manager)
