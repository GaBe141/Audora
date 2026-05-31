"""Integration tests for Last.fm API client (mocked HTTP)."""

import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

# Last.fm module imports from .config which may not exist; provide a minimal mock
if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from core.exceptions import APIConnectionError, APIResponseError
from integrations.lastfm_integration import BASE_URL, LastFmAPI


def test_lastfm_base_url_uses_https():
    """Last.fm API keys are sent as query params and must not use plaintext HTTP."""
    assert BASE_URL.startswith("https://")


class TestLastFmAPISuccess:
    """Test successful API responses with mocked session.get."""

    def test_get_top_artists_global_parses_response(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "artists": {
                "artist": [
                    {
                        "name": "Artist One",
                        "playcount": "100000",
                        "listeners": "5000",
                        "url": "https://example.com",
                        "mbid": "mbid-1",
                    },
                ],
            },
        }
        with patch.object(api.session, "get", return_value=mock_response) as get:
            df = api.get_top_artists_global(limit=5)
        assert not df.empty
        assert len(df) == 1
        assert df.iloc[0]["name"] == "Artist One"
        assert df.iloc[0]["playcount"] == 100000
        assert "rank" in df.columns
        assert get.call_args.args[0] == BASE_URL
        assert get.call_args.args[0].startswith("https://")

    def test_get_top_tracks_global_parses_response(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "tracks": {
                "track": [
                    {
                        "name": "Track One",
                        "artist": {"name": "Artist One"},
                        "playcount": "50000",
                        "listeners": "3000",
                        "url": "",
                        "mbid": "",
                    },
                ],
            },
        }
        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_tracks_global(limit=5)
        assert not df.empty
        assert df.iloc[0]["name"] == "Track One"
        assert df.iloc[0]["artist"] == "Artist One"


class TestLastFmAPIErrorHandling:
    """Test API error and HTTP error handling."""

    def test_api_error_in_json_raises_response_error(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"error": 10, "message": "Invalid API key"}
        with (
            patch.object(api.session, "get", return_value=mock_response),
            pytest.raises(APIResponseError, match="Invalid API key"),
        ):
            api.get_top_artists_global(limit=5)

    def test_http_error_raises_connection_error(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("429")
        with (
            patch.object(api.session, "get", return_value=mock_response),
            pytest.raises(APIConnectionError, match="429"),
        ):
            api.get_top_artists_global(limit=5)

    def test_http_error_does_not_leak_api_key(self, caplog):
        api = LastFmAPI(api_key="SECRET_LASTFM_KEY")
        mock_response = MagicMock()
        http_error = requests.exceptions.HTTPError(
            "403 Client Error: Forbidden for url: "
            "https://ws.audioscrobbler.com/2.0/?api_key=SECRET_LASTFM_KEY"
        )
        http_error.response = MagicMock(status_code=403)
        mock_response.raise_for_status.side_effect = http_error

        with (
            patch.object(api.session, "get", return_value=mock_response),
            pytest.raises(APIConnectionError) as exc_info,
        ):
            api.get_top_artists_global(limit=5)

        assert "SECRET_LASTFM_KEY" not in str(exc_info.value)
        assert "SECRET_LASTFM_KEY" not in caplog.text
        assert exc_info.value.details["status_code"] == 403
