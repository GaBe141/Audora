"""Integration tests for MusicBrainz API client (mocked HTTP)."""

from unittest.mock import MagicMock, patch

from integrations.musicbrainz_integration import MusicBrainzAPI


class TestMusicBrainzAPISuccess:
    """Test successful API responses with mocked session.get."""

    def test_search_artist_parses_response(self):
        api = MusicBrainzAPI()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "artists": [
                {
                    "id": "mbid-123",
                    "name": "Test Artist",
                    "type": "Person",
                },
            ],
        }
        with patch.object(api.session, "get", return_value=mock_response):
            result = api.search_artist("Test Artist")
        assert result is not None
        assert result["name"] == "Test Artist"
        assert result["id"] == "mbid-123"

    def test_search_artist_empty_returns_none(self):
        api = MusicBrainzAPI()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"artists": []}
        with patch.object(api.session, "get", return_value=mock_response):
            result = api.search_artist("Unknown")
        assert result is None


class TestMusicBrainzAPIErrorHandling:
    """Test HTTP and request errors return None or empty."""

    def test_http_error_returns_none(self):
        import requests

        api = MusicBrainzAPI()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("503")
        with patch.object(api.session, "get", return_value=mock_response):
            result = api.search_artist("Any")
        assert result is None
