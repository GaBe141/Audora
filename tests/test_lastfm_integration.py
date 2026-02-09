"""Integration tests for Last.fm API client (mocked HTTP)."""

import sys
from unittest.mock import MagicMock, patch

# Last.fm module imports from .config which may not exist; provide a minimal mock
if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from integrations.lastfm_integration import LastFmAPI


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
        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_artists_global(limit=5)
        assert not df.empty
        assert len(df) == 1
        assert df.iloc[0]["name"] == "Artist One"
        assert df.iloc[0]["playcount"] == 100000
        assert "rank" in df.columns

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

    def test_api_error_in_json_returns_empty_dataframe(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"error": 10, "message": "Invalid API key"}
        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_artists_global(limit=5)
        assert df.empty

    def test_http_error_returns_empty_dataframe(self):
        import requests

        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("429")
        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_artists_global(limit=5)
        assert df.empty
