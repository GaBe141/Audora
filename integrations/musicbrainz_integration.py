"""MusicBrainz API integration for comprehensive music metadata and artist relationships."""

import time
from typing import Any

import pandas as pd
import requests

BASE_URL = "https://musicbrainz.org/ws/2/"
USER_AGENT = "SpotifyInsights/1.0 (https://github.com/GaBe141/spotify-insights)"


class MusicBrainzAPI:
    """MusicBrainz API client with rate limiting and comprehensive metadata fetching."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.last_request_time = 0
        self.rate_limit_delay = 1.0  # 1 request per second to be respectful

    def _rate_limit(self):
        """Ensure we don't exceed rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: dict[str, Any]) -> dict | None:
        """Make a request to MusicBrainz API with rate limiting."""
        self._rate_limit()

        params.update({"fmt": "json"})

        try:
            response = self.session.get(f"{BASE_URL}{endpoint}", params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"MusicBrainz API error: {e}")
            return None

    def search_artist(self, artist_name: str) -> dict | None:
        """Search for an artist by name."""
        params = {"query": f'artist:"{artist_name}"', "limit": 1}

        result = self._make_request("artist", params)
        if result and result.get("artists"):
            return result["artists"][0]
        return None

    def get_artist_details(self, mbid: str) -> dict | None:
        """Get detailed artist information including relationships."""
        params = {
            "inc": "artist-rels+recording-rels+release-rels+work-rels+url-rels+tags+ratings+genres"
        }

        return self._make_request(f"artist/{mbid}", params)

    def get_artist_releases(self, mbid: str) -> list[dict]:
        """Get all releases for an artist."""
        params = {"artist": mbid, "inc": "release-groups+media+recordings", "limit": 100}

        result = self._make_request("release", params)
        if result and result.get("releases"):
            return result["releases"]
        return []

    def get_related_artists(self, mbid: str) -> list[dict]:
        """Get artists related to the given artist through various relationships."""
        artist_details = self.get_artist_details(mbid)
        if not artist_details or "relations" not in artist_details:
            return []

        related_artists = []
        for relation in artist_details["relations"]:
            if relation.get("type") in ["member", "collaboration", "founder", "collaboration"]:
                if "artist" in relation:
                    related_artists.append(
                        {
                            "name": relation["artist"]["name"],
                            "mbid": relation["artist"]["id"],
                            "relationship_type": relation["type"],
                            "direction": relation.get("direction", "forward"),
                        }
                    )

        return related_artists

    def analyze_artist_network(self, artist_names: list[str]) -> pd.DataFrame:
        """Analyze the network of relationships between multiple artists."""
        network_data = []

        print(f"🔍 Analyzing MusicBrainz network for {len(artist_names)} artists...")

        for i, artist_name in enumerate(artist_names):
            print(f"Processing {i+1}/{len(artist_names)}: {artist_name}")

            # Find artist
            artist = self.search_artist(artist_name)
            if not artist:
                continue

            # Get related artists
            related = self.get_related_artists(artist["id"])

            for rel in related:
                network_data.append(
                    {
                        "source_artist": artist_name,
                        "source_mbid": artist["id"],
                        "target_artist": rel["name"],
                        "target_mbid": rel["mbid"],
                        "relationship_type": rel["relationship_type"],
                        "direction": rel["direction"],
                    }
                )

        return pd.DataFrame(network_data)

    def get_artist_metadata_enrichment(self, artist_names: list[str]) -> pd.DataFrame:
        """Enrich artist data with comprehensive MusicBrainz metadata."""
        enriched_data = []

        print(f"🎵 Enriching {len(artist_names)} artists with MusicBrainz metadata...")

        for i, artist_name in enumerate(artist_names):
            print(f"Processing {i+1}/{len(artist_names)}: {artist_name}")

            # Search for artist
            artist = self.search_artist(artist_name)
            if not artist:
                enriched_data.append(
                    {
                        "artist_name": artist_name,
                        "mbid": None,
                        "country": None,
                        "begin_date": None,
                        "end_date": None,
                        "type": None,
                        "gender": None,
                        "disambiguation": None,
                        "tags": None,
                        "release_count": 0,
                    }
                )
                continue

            # Get detailed info
            details = self.get_artist_details(artist["id"])
            releases = self.get_artist_releases(artist["id"])

            # Extract tags
            tags = []
            if details and "tags" in details:
                tags = [tag["name"] for tag in details["tags"][:10]]  # Top 10 tags

            enriched_data.append(
                {
                    "artist_name": artist_name,
                    "mbid": artist["id"],
                    "country": artist.get("country"),
                    "begin_date": artist.get("life-span", {}).get("begin"),
                    "end_date": artist.get("life-span", {}).get("end"),
                    "type": artist.get("type"),
                    "gender": artist.get("gender"),
                    "disambiguation": artist.get("disambiguation"),
                    "tags": ", ".join(tags) if tags else None,
                    "release_count": len(releases),
                }
            )

        return pd.DataFrame(enriched_data)


def get_musicbrainz_client() -> MusicBrainzAPI:
    """Get MusicBrainz API client (no authentication required)."""
    return MusicBrainzAPI()


def enrich_spotify_artists_with_musicbrainz(spotify_df: pd.DataFrame) -> pd.DataFrame:
    """Enrich Spotify artist data with MusicBrainz metadata."""
    client = get_musicbrainz_client()

    # Get unique artist names
    artist_names = spotify_df["artist_name"].unique().tolist()

    # Get enrichment data
    enrichment_df = client.get_artist_metadata_enrichment(artist_names)

    # Merge with original data
    enriched_df = spotify_df.merge(enrichment_df, on="artist_name", how="left")

    return enriched_df


def analyze_artist_relationships(artist_names: list[str]) -> dict[str, pd.DataFrame]:
    """Analyze relationships between artists using MusicBrainz data."""
    client = get_musicbrainz_client()

    print("🕸️ Analyzing artist relationship networks...")

    # Get network data
    network_df = client.analyze_artist_network(artist_names)

    # Create summary statistics
    if not network_df.empty:
        relationship_summary = (
            network_df.groupby("relationship_type").size().reset_index(name="count")
        )
        artist_connections = (
            network_df.groupby("source_artist").size().reset_index(name="connection_count")
        )
    else:
        relationship_summary = pd.DataFrame()
        artist_connections = pd.DataFrame()

    return {
        "network": network_df,
        "relationship_summary": relationship_summary,
        "artist_connections": artist_connections,
    }


if __name__ == "__main__":
    # Test the MusicBrainz integration
    client = get_musicbrainz_client()

    test_artists = ["The Beatles", "Radiohead", "Kendrick Lamar"]

    print("Testing MusicBrainz integration...")

    # Test artist search
    for artist in test_artists:
        result = client.search_artist(artist)
        if result:
            print(f"✅ Found {artist}: {result['name']} (MBID: {result['id']})")
        else:
            print(f"❌ Could not find {artist}")

    # Test enrichment
    df = pd.DataFrame({"artist_name": test_artists})
    enriched = client.get_artist_metadata_enrichment(test_artists)
    print(f"\n✅ Enriched {len(enriched)} artists with metadata")
    print(enriched[["artist_name", "country", "type", "release_count"]].to_string())
