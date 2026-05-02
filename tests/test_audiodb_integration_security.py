"""Security-focused tests for AudioDB API integration."""

from unittest.mock import MagicMock, patch

from integrations.audiodb_integration import AudioDBAPI, REQUEST_TIMEOUT


def test_audiodb_requests_use_bounded_timeout():
    api = AudioDBAPI(api_key="test")
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"artists": []}

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.search_artist("Test Artist")

    assert mock_get.call_args.kwargs["timeout"] == REQUEST_TIMEOUT
