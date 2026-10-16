"""Spotify authentication module with secure configuration."""

import os
from pathlib import Path

import spotipy
from spotipy.cache_handler import CacheFileHandler
from spotipy.oauth2 import SpotifyOAuth

from .config import get_config
from .utils import confine_path, project_root


def spotify_token_cache_path() -> Path:
    """Return the project-local Spotify token cache, created with mode 600.

    The cache must not follow the process working directory. A planted or
    world-readable ``.cache`` file in that directory can steal or replace
    OAuth refresh tokens.
    """
    candidate = project_root() / ".cache"
    if candidate.is_symlink():
        raise ValueError("Spotify token cache must not be a symlink")
    cache_path = confine_path(candidate)
    if cache_path.exists() and not cache_path.is_file():
        raise ValueError("Spotify token cache path must be a file")
    if not cache_path.exists():
        cache_path.touch(mode=0o600, exist_ok=True)
    if os.name != "nt":
        cache_path.chmod(0o600)
    return cache_path


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
    cache_path = spotify_token_cache_path()

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
