"""Security tests for auth token cache handling."""

from pathlib import Path

from core.auth import _resolve_spotify_cache_path


def test_spotify_cache_path_uses_private_user_cache(monkeypatch):
    """Default cache path should be user-private and outside repository root."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    path = _resolve_spotify_cache_path()

    assert path.name == "spotify_oauth.cache"
    assert "audora" in path.parts
    assert path.is_absolute()
    assert str(path).startswith(str(Path.home()))


def test_spotify_cache_path_respects_xdg_cache_home(monkeypatch):
    """XDG cache home should be preferred when explicitly set."""
    monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/custom-cache-home")
    path = _resolve_spotify_cache_path()

    assert path == Path("/tmp/custom-cache-home/audora/spotify_oauth.cache")
