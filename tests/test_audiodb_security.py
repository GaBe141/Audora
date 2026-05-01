"""Security-focused tests for AudioDB HTTP requests."""

from unittest.mock import MagicMock, patch

from integrations.audiodb_integration import AudioDBAPI, REQUEST_TIMEOUT_SECONDS


def test_audiodb_requests_use_timeout():
    api = AudioDBAPI(api_key="123")
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"artists": []}

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.search_artist("Test Artist")

    _, kwargs = mock_get.call_args
    assert kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS
