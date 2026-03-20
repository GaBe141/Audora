"""Spotify authentication module with secure configuration."""

import os
from pathlib import Path

import spotipy
from spotipy.oauth2 import SpotifyOAuth

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

    cache_path = ".cache"
    auth_manager = SpotifyOAuth(
        client_id=spotify_config["client_id"],
        client_secret=spotify_config["client_secret"],
        redirect_uri=spotify_config["redirect_uri"],
        scope=spotify_config["scopes"],
        cache_path=cache_path,  # token cache in project root
        open_browser=True,
        show_dialog=False,
    )

    # Harden local token cache permissions when possible.
    cache_file = Path(cache_path)
    if cache_file.exists() and os.name != "nt":
        try:
            os.chmod(cache_file, 0o600)
        except OSError:
            pass

    return spotipy.Spotify(auth_manager=auth_manager)
