"""Spotify authentication module with secure configuration."""

import secrets

import requests
import spotipy
import urllib3
from spotipy.oauth2 import SpotifyOAuth

from core.utils import (
    PROJECT_ROOT,
    JsonTokenCache,
    credentialed_requests_session,
    credentialed_tls_adapter,
)

from .config import get_config

# Match Spotipy's default client retry policy. The auth session does not retry:
# a second POST would replay the authorization code or refresh token.
_API_RETRY = urllib3.Retry(
    total=3,
    connect=None,
    read=False,
    allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE"]),
    status=3,
    backoff_factor=0.3,
    status_forcelist=(429, 500, 502, 503, 504),
)


def _spotify_api_session() -> requests.Session:
    """API session with Spotipy's retries, still blind to proxy env, redirects, and key logs.

    Replacing the mounted adapter with a stock ``HTTPAdapter`` would let urllib3
    write TLS session keys again. The auth session stays separate and does not retry.
    """
    session = credentialed_requests_session()
    adapter = credentialed_tls_adapter(max_retries=_API_RETRY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_client() -> spotipy.Spotify:
    """Create an authenticated Spotipy client using secure configuration.

    Uses the SecureConfig class to safely load credentials from environment.
    Both the token request and later API calls use a session that ignores
    ``HTTPS_PROXY`` / ``REQUESTS_CA_BUNDLE`` and does not follow redirects.
    Spotipy's default session would send the client secret and refresh token
    through those channels.

    ``state`` is a fresh unguessable value on every client. Spotipy's localhost
    callback accepts the first ``code`` it receives and, when ``state`` is
    omitted, does not check where that code came from. Another page on the
    machine can submit its own authorization code during login and bind this
    app to a different Spotify account.

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
        state=secrets.token_urlsafe(32),
        cache_handler=JsonTokenCache(PROJECT_ROOT / ".cache"),
        open_browser=True,
        show_dialog=False,
        requests_session=credentialed_requests_session(),
    )

    return spotipy.Spotify(auth_manager=auth_manager, requests_session=_spotify_api_session())
