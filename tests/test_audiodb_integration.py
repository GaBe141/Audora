"""Integration tests for AudioDB API client security defaults."""

from unittest.mock import MagicMock, patch

from integrations.audiodb_integration import AudioDBAPI


class TestAudioDBAPIRequestSecurity:
    """Test outbound request safety defaults."""

    def test_requests_use_explicit_timeout(self):
        api = AudioDBAPI(api_key="123")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"artists": []}

        with patch.object(api.session, "get", return_value=mock_response) as mock_get:
            api.search_artist("Test Artist")

        assert mock_get.call_args.kwargs["timeout"] == (3.05, 15)
