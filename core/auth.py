"""Spotify authentication module with secure configuration."""

import os
from pathlib import Path

import spotipy
from spotipy.cache_handler import CacheFileHandler
from spotipy.oauth2 import SpotifyOAuth

from .config import get_config


def _secure_cache_file_path(cache_path: Path) -> Path:
    """Return a writable token cache file path with restrictive permissions."""
    target_path = cache_path
    if target_path.exists() and target_path.is_dir():
        target_path = target_path / "spotify_token_cache"

    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Prevent writing OAuth tokens through symlink targets.
    if target_path.exists() and target_path.is_symlink():
        raise ValueError(f"Refusing to use symlink for Spotify token cache: {target_path}")

    if not target_path.exists():
        target_path.touch(exist_ok=True)

    if os.name != "nt":
        os.chmod(target_path, 0o600)

    return target_path


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
    cache_file = _secure_cache_file_path(Path(".cache"))

    auth_manager = SpotifyOAuth(
        client_id=spotify_config["client_id"],
        client_secret=spotify_config["client_secret"],
        redirect_uri=spotify_config["redirect_uri"],
        scope=spotify_config["scopes"],
        cache_handler=CacheFileHandler(cache_path=str(cache_file)),
        open_browser=True,
        show_dialog=False,
    )

    return spotipy.Spotify(auth_manager=auth_manager)
