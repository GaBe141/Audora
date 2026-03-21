"""Security hardening tests for external HTTP integrations."""

from unittest.mock import MagicMock, patch

from integrations.audiodb_integration import AudioDBAPI, REQUEST_TIMEOUT_SECONDS as AUDIODB_TIMEOUT
from integrations.musicbrainz_integration import (
    REQUEST_TIMEOUT_SECONDS as MUSICBRAINZ_TIMEOUT,
    MusicBrainzAPI,
)
from integrations.spotify_charts_integration import (
    REQUEST_TIMEOUT_SECONDS as SPOTIFY_CHARTS_TIMEOUT,
    SpotifyChartsAPI,
)


def test_audiodb_requests_use_explicit_timeout():
    api = AudioDBAPI(api_key="test_key")
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"artists": []}

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.search_artist("Test Artist")

    assert mock_get.call_args.kwargs["timeout"] == AUDIODB_TIMEOUT


def test_musicbrainz_requests_use_explicit_timeout():
    api = MusicBrainzAPI()
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"artists": []}

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.search_artist("Test Artist")

    assert mock_get.call_args.kwargs["timeout"] == MUSICBRAINZ_TIMEOUT


def test_spotify_charts_top_200_requests_use_explicit_timeout():
    api = SpotifyChartsAPI()
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.content = b"<html><body></body></html>"

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.get_top_200_daily(country_code="global", date="2026-01-01")

    assert mock_get.call_args.kwargs["timeout"] == SPOTIFY_CHARTS_TIMEOUT


def test_spotify_charts_viral_requests_use_explicit_timeout():
    api = SpotifyChartsAPI()
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.content = b"<html><body></body></html>"

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.get_viral_50_daily(country_code="global", date="2026-01-01")

    assert mock_get.call_args.kwargs["timeout"] == SPOTIFY_CHARTS_TIMEOUT
