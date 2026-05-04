"""Security tests for the Last.fm integration."""

import requests
import pytest

from core.exceptions import APIConnectionError
from integrations.lastfm_integration import BASE_URL, LastFmAPI


def test_lastfm_uses_https_transport():
    assert BASE_URL.startswith("https://")


def test_lastfm_request_errors_do_not_expose_api_key():
    api_key = "super-secret-lastfm-key"
    client = LastFmAPI(api_key)

    response = requests.Response()
    response.status_code = 500
    response.url = f"{BASE_URL}?method=chart.gettoptracks&api_key={api_key}&format=json"
    error = requests.exceptions.HTTPError("500 Server Error", response=response)

    def fail_request(*_args, **_kwargs):
        raise error

    client.session.get = fail_request

    with pytest.raises(APIConnectionError) as exc_info:
        client._make_request("chart.gettoptracks")

    assert api_key not in str(exc_info.value)
    assert exc_info.value.details == {
        "method": "chart.gettoptracks",
        "status_code": 500,
    }
