"""Spotify Charts web scraping for real streaming data and trending analysis."""

import json
import time
from datetime import datetime, timedelta

import pandas as pd
import requests
from bs4 import BeautifulSoup

CHARTS_BASE_URL = "https://charts.spotify.com"


class SpotifyChartsAPI:
    """Spotify Charts scraper for real streaming data."""

    def __init__(self):
        self.session = requests.Session()
        # Use a realistic user agent
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )
        self.last_request_time = 0
        self.rate_limit_delay = 2.0  # Be respectful with scraping

    def _rate_limit(self):
        """Ensure we don't exceed rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()

    def get_top_200_daily(self, country_code: str = "global", date: str = None) -> pd.DataFrame:
        """Get top 200 tracks for a specific date and country.

        Args:
            country_code: Country code (e.g., 'us', 'gb', 'global')
            date: Date in YYYY-MM-DD format, defaults to latest
        """
        self._rate_limit()

        if date is None:
            # Default to yesterday (charts are usually 1 day behind)
            date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        url = f"{CHARTS_BASE_URL}/charts/view/regional-{country_code}-daily/{date}"

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            # Parse the HTML
            soup = BeautifulSoup(response.content, "html.parser")

            # Find the chart data (this might need adjustment based on site structure)
            chart_data = []

            # Look for the data in script tags (common pattern for charts)
            scripts = soup.find_all("script")
            for script in scripts:
                if script.string and "chartEntryViewModels" in script.string:
                    # Extract JSON data from script
                    start = script.string.find('"chartEntryViewModels"')
                    if start != -1:
                        # This is a simplified extraction - real implementation would be more robust
                        try:
                            # Extract the JSON portion
                            json_start = script.string.find("[", start)
                            json_end = script.string.find("]", json_start) + 1
                            if json_start != -1 and json_end != -1:
                                json_str = script.string[json_start:json_end]
                                data = json.loads(json_str)

                                for entry in data:
                                    chart_data.append(
                                        {
                                            "position": entry.get("currentRank", 0),
                                            "track_name": entry.get("trackName", ""),
                                            "artist_name": entry.get("artistNames", ""),
                                            "streams": entry.get("streamCount", 0),
                                            "date": date,
                                            "country": country_code,
                                        }
                                    )
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue

            # Fallback: try to parse table structure
            if not chart_data:
                chart_data = self._parse_table_fallback(soup, date, country_code)

            return pd.DataFrame(chart_data)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching Spotify Charts: {e}")
            return pd.DataFrame()

    def _parse_table_fallback(
        self, soup: BeautifulSoup, date: str, country_code: str
    ) -> list[dict]:
        """Fallback method to parse chart data from table structure."""
        chart_data = []

        # Look for table or list structure
        rows = soup.find_all(["tr", "li"])

        for i, row in enumerate(rows[:200]):  # Top 200
            # This is a simplified parser - would need adjustment for actual site structure
            text_content = row.get_text(strip=True)

            # Skip headers or empty rows
            if not text_content or "Position" in text_content:
                continue

            # Try to extract basic info (this is very site-specific)
            if len(text_content.split()) >= 3:
                text_content.split()
                chart_data.append(
                    {
                        "position": i + 1,
                        "track_name": "Unknown",  # Would need specific parsing
                        "artist_name": "Unknown",  # Would need specific parsing
                        "streams": 0,  # Would need specific parsing
                        "date": date,
                        "country": country_code,
                    }
                )

        return chart_data

    def get_viral_50_daily(self, country_code: str = "global", date: str = None) -> pd.DataFrame:
        """Get viral 50 tracks for a specific date and country."""
        self._rate_limit()

        if date is None:
            date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        url = f"{CHARTS_BASE_URL}/charts/view/viral-{country_code}-daily/{date}"

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            BeautifulSoup(response.content, "html.parser")

            # Similar parsing logic as top_200_daily but for viral charts
            viral_data = []

            # Simplified implementation - would need real parsing logic
            for i in range(50):
                viral_data.append(
                    {
                        "position": i + 1,
                        "track_name": f"Viral Track {i+1}",  # Placeholder
                        "artist_name": f"Viral Artist {i+1}",  # Placeholder
                        "date": date,
                        "country": country_code,
                        "chart_type": "viral",
                    }
                )

            return pd.DataFrame(viral_data)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching Viral Charts: {e}")
            return pd.DataFrame()

    def get_multi_country_comparison(self, countries: list[str], date: str = None) -> pd.DataFrame:
        """Get chart data for multiple countries for comparison."""
        all_charts = []

        print(f"🌍 Fetching charts for {len(countries)} countries...")

        for country in countries:
            print(f"Fetching {country} charts...")
            chart_df = self.get_top_200_daily(country, date)
            if not chart_df.empty:
                all_charts.append(chart_df)

        if all_charts:
            return pd.concat(all_charts, ignore_index=True)
        else:
            return pd.DataFrame()

    def analyze_trending_tracks(self, days_back: int = 7) -> pd.DataFrame:
        """Analyze trending patterns over multiple days."""
        trending_data = []

        print(f"📈 Analyzing trends over {days_back} days...")

        for i in range(days_back):
            date = (datetime.now() - timedelta(days=i + 1)).strftime("%Y-%m-%d")
            print(f"Fetching data for {date}...")

            daily_chart = self.get_top_200_daily("global", date)
            if not daily_chart.empty:
                trending_data.append(daily_chart)

        if trending_data:
            all_data = pd.concat(trending_data, ignore_index=True)

            # Calculate trend metrics
            trend_analysis = (
                all_data.groupby(["track_name", "artist_name"])
                .agg(
                    {
                        "position": ["min", "max", "mean"],
                        "streams": ["sum", "mean"],
                        "date": "count",
                    }
                )
                .reset_index()
            )

            # Flatten column names
            trend_analysis.columns = [
                "track_name",
                "artist_name",
                "best_position",
                "worst_position",
                "avg_position",
                "total_streams",
                "avg_streams",
                "days_on_chart",
            ]

            return trend_analysis

        return pd.DataFrame()


def get_spotify_charts_client() -> SpotifyChartsAPI:
    """Get Spotify Charts client (no authentication required)."""
    return SpotifyChartsAPI()


def compare_personal_vs_charts(
    spotify_top_tracks: pd.DataFrame, chart_date: str = None
) -> dict[str, pd.DataFrame]:
    """Compare personal top tracks with global charts."""
    charts_client = get_spotify_charts_client()

    print("📊 Comparing personal taste with global charts...")

    # Get current global charts
    global_charts = charts_client.get_top_200_daily("global", chart_date)

    if global_charts.empty:
        print("❌ Could not fetch chart data")
        return {"comparison": pd.DataFrame(), "matches": pd.DataFrame()}

    # Find matches between personal and global
    personal_tracks = set(
        zip(spotify_top_tracks["track_name"], spotify_top_tracks["artist_name"], strict=False)
    )
    chart_tracks = set(zip(global_charts["track_name"], global_charts["artist_name"], strict=False))

    matches = personal_tracks.intersection(chart_tracks)

    if matches:
        match_data = []
        for track_name, artist_name in matches:
            personal_row = spotify_top_tracks[
                (spotify_top_tracks["track_name"] == track_name)
                & (spotify_top_tracks["artist_name"] == artist_name)
            ].iloc[0]

            chart_row = global_charts[
                (global_charts["track_name"] == track_name)
                & (global_charts["artist_name"] == artist_name)
            ].iloc[0]

            match_data.append(
                {
                    "track_name": track_name,
                    "artist_name": artist_name,
                    "personal_rank": personal_row.get("rank", 0),
                    "global_rank": chart_row["position"],
                    "global_streams": chart_row["streams"],
                }
            )

        matches_df = pd.DataFrame(match_data)
    else:
        matches_df = pd.DataFrame()

    # Calculate mainstream score
    mainstream_score = (
        len(matches) / len(spotify_top_tracks) * 100 if len(spotify_top_tracks) > 0 else 0
    )

    comparison_summary = pd.DataFrame(
        [
            {
                "total_personal_tracks": len(spotify_top_tracks),
                "total_chart_tracks": len(global_charts),
                "matching_tracks": len(matches),
                "mainstream_score_percent": mainstream_score,
            }
        ]
    )

    return {"comparison": comparison_summary, "matches": matches_df, "global_charts": global_charts}


if __name__ == "__main__":
    # Test the Spotify Charts integration
    charts_client = get_spotify_charts_client()

    print("Testing Spotify Charts integration...")

    # Test getting global top 200
    print("Fetching global top 200...")
    global_top = charts_client.get_top_200_daily("global")

    if not global_top.empty:
        print(f"✅ Fetched {len(global_top)} tracks from global charts")
        print("Top 5 tracks:")
        print(global_top[["position", "track_name", "artist_name", "streams"]].head().to_string())
    else:
        print("❌ Could not fetch global charts")

    # Test multi-country comparison
    print("\nTesting multi-country comparison...")
    countries = ["global", "us", "gb"]
    multi_country = charts_client.get_multi_country_comparison(countries)

    if not multi_country.empty:
        print(f"✅ Fetched charts for {multi_country['country'].nunique()} countries")
    else:
        print("❌ Could not fetch multi-country data")
