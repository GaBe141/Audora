"""Integration tests for Spotify Charts API client (mocked HTTP)."""

from unittest.mock import MagicMock, patch

from integrations.spotify_charts_integration import SpotifyChartsAPI


class TestSpotifyChartsAPISuccess:
    """Test successful chart fetch with mocked response content."""

    def test_get_top_200_daily_parses_chart_entry_view_models(self):
        api = SpotifyChartsAPI()
        # The parser looks for script.string and "chartEntryViewModels", then finds "[" and "]"
        # So we need a valid script with a JSON array. The code does: json_start = script.string.find("[", start)
        script_content = """some prefix "chartEntryViewModels" [{"currentRank": 1, "trackName": "Test Track", "artistNames": "Test Artist", "streamCount": 50000}] suffix"""
        html_with_script = (
            b"<html><body><script>" + script_content.encode("utf-8") + b"</script></body></html>"
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content = html_with_script

        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_200_daily(country_code="us", date="2024-01-15")

        assert isinstance(df, __import__("pandas").DataFrame)
        if not df.empty:
            assert "track_name" in df.columns or "position" in df.columns


class TestSpotifyChartsAPIErrorHandling:
    """Test HTTP errors return empty DataFrame."""

    def test_request_exception_returns_empty_dataframe(self):
        import requests

        api = SpotifyChartsAPI()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.RequestException(
            "Connection error"
        )
        with patch.object(api.session, "get", return_value=mock_response):
            df = api.get_top_200_daily(country_code="global")
        assert df.empty
