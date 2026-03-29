"""Security-focused tests for Last.fm integration."""

from integrations.lastfm_integration import BASE_URL


def test_lastfm_base_url_uses_https() -> None:
    """Transport to Last.fm must use HTTPS."""
    assert BASE_URL.startswith("https://")
