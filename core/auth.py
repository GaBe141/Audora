"""Spotify authentication module with secure configuration."""

import os
from pathlib import Path

import spotipy
from spotipy.oauth2 import SpotifyOAuth

from .config import get_config


def _get_secure_token_cache_path() -> str:
    """Return a cache file path with restrictive permissions."""
    cache_dir = Path.home() / ".cache" / "audora"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Best-effort permissions hardening on Unix-like systems.
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass

    cache_file = cache_dir / "spotify_token.cache"
    if not cache_file.exists():
        cache_file.touch(mode=0o600, exist_ok=True)

    try:
        os.chmod(cache_file, 0o600)
    except OSError:
        pass

    return str(cache_file)


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
        cache_path=_get_secure_token_cache_path(),
        open_browser=True,
        show_dialog=False,
    )

    return spotipy.Spotify(auth_manager=auth_manager)
