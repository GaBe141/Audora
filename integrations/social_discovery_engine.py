"""
Multi-platform social media music discovery engine.
Integrates TikTok, YouTube, Instagram, Twitter, and other platforms to track Gen Z/Alpha music trends.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import aiohttp

from core.utils import write_json

# Import our existing trending schema
from integrations.trending_schema import TrendingSchema


class Platform(Enum):
    """Social media platforms for music discovery."""

    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    SOUNDCLOUD = "soundcloud"
    REDDIT = "reddit"
    TUMBLR = "tumblr"
    DISCORD = "discord"
    PINTEREST = "pinterest"
    SHAZAM = "shazam"


class ViralStage(Enum):
    """Stages of viral music progression."""

    UNDERGROUND = "underground"
    EMERGING = "emerging"
    NICHE_VIRAL = "niche_viral"
    PLATFORM_VIRAL = "platform_viral"
    CROSS_PLATFORM = "cross_platform"
    MAINSTREAM = "mainstream"
    OVERSATURATED = "oversaturated"


@dataclass
class SocialMusicMetrics:
    """Metrics for a song across social platforms."""

    platform: Platform
    song_id: str
    artist_name: str
    song_title: str

    # Engagement metrics
    views: int = 0
    likes: int = 0
    shares: int = 0
    comments: int = 0
    saves: int = 0

    # Platform-specific metrics
    video_uses: int = 0  # TikTok/Instagram Reels
    hashtag_mentions: int = 0
    playlist_adds: int = 0

    # Timing metrics
    timestamp: datetime | None = None
    trend_velocity: float = 0.0  # Rate of growth
    viral_stage: ViralStage = ViralStage.UNDERGROUND

    # Demographics
    primary_age_group: str = "unknown"  # "13-17", "18-24", "25-34", etc.
    top_regions: list[str] | None = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.top_regions is None:
            self.top_regions = []
        if self.top_regions is None:
            self.top_regions = []


@dataclass
class CrossPlatformTrend:
    """Track how a song trends across multiple platforms."""

    song_id: str
    artist_name: str
    song_title: str

    # Platform progression
    origin_platform: Platform
    current_platforms: list[Platform]
    viral_progression: list[tuple[Platform, datetime, ViralStage]]

    # Aggregated metrics
    total_engagement: int = 0
    cross_platform_velocity: float = 0.0
    predicted_mainstream_date: datetime | None = None

    # Discovery patterns
    discovery_pattern: str = "unknown"  # "tiktok_first", "youtube_shorts", "instagram_reels"
    influencer_driven: bool = False
    organic_growth: bool = True


class TikTokMusicAPI:
    """TikTok Research API integration for music discovery."""

    def __init__(self, api_key: str, secret: str):
        self.api_key = api_key
        self.secret = secret
        self.base_url = "https://open.tiktokapis.com/v2"
        self.session = None

    async def get_trending_sounds(
        self, region: str = "US", count: int = 100
    ) -> list[dict[str, Any]]:
        """Get trending audio clips and music on TikTok."""
        endpoint = f"{self.base_url}/research/music/trending/"

        params = {
            "region_code": str(region),
            "count": str(count),
            "fields": "music_id,title,artist,play_count,video_count,trend_score",
        }

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(endpoint, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", [])
                    else:
                        print(f"TikTok API error: {response.status}")
                        return []
        except Exception as e:
            print(f"TikTok API exception: {e}")
            return []

    async def get_sound_analytics(self, sound_id: str) -> dict[str, Any]:
        """Get detailed analytics for a specific sound."""
        endpoint = f"{self.base_url}/research/music/analytics/"

        params = {
            "sound_id": str(sound_id),
            "fields": "video_count,play_count,share_count,hashtag_count,age_distribution,region_distribution",
        }

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(endpoint, params=params, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"API error: {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def track_hashtag_music(self, hashtag: str) -> list[dict[str, Any]]:
        """Track music associated with trending hashtags."""
        endpoint = f"{self.base_url}/research/hashtag/music/"

        params = {
            "hashtag": hashtag,
            "count": 50,
            "fields": "music_id,title,artist,video_count,engagement_rate",
        }

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(endpoint, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", [])
                    else:
                        return []
        except Exception as e:
            print(f"Hashtag music tracking error: {e}")
            return []


class YouTubeMusicAPI:
    """YouTube Data API v3 integration for music discovery."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.googleapis.com/youtube/v3"

    async def get_trending_music_videos(
        self, region: str = "US", max_results: int = 50
    ) -> list[dict[str, Any]]:
        """Get trending music videos."""
        endpoint = f"{self.base_url}/videos"

        params = {
            "part": "snippet,statistics,contentDetails",
            "chart": "mostPopular",
            "videoCategoryId": "10",  # Music category
            "regionCode": region,
            "maxResults": max_results,
            "key": self.api_key,
        }

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(endpoint, params=params) as response,
            ):
                if response.status == 200:
                    data = await response.json()
                    return data.get("items", [])
                else:
                    print(f"YouTube API error: {response.status}")
                    return []
        except Exception as e:
            print(f"YouTube API exception: {e}")
            return []

    async def search_music_by_keyword(
        self, query: str, max_results: int = 25
    ) -> list[dict[str, Any]]:
        """Search for music videos by keyword."""
        endpoint = f"{self.base_url}/search"

        params = {
            "part": "snippet",
            "q": query,
            "type": "video",
            "videoCategoryId": "10",
            "order": "relevance",
            "maxResults": max_results,
            "key": self.api_key,
        }

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(endpoint, params=params) as response,
            ):
                if response.status == 200:
                    data = await response.json()
                    return data.get("items", [])
                else:
                    return []
        except Exception as e:
            print(f"YouTube search error: {e}")
            return []

    async def get_video_analytics(self, video_id: str) -> dict[str, Any]:
        """Get detailed analytics for a specific video."""
        endpoint = f"{self.base_url}/videos"

        params = {
            "part": "snippet,statistics,contentDetails,status",
            "id": video_id,
            "key": self.api_key,
        }

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(endpoint, params=params) as response,
            ):
                if response.status == 200:
                    data = await response.json()
                    items = data.get("items", [])
                    return items[0] if items else {}
                else:
                    return {"error": f"API error: {response.status}"}
        except Exception as e:
            return {"error": str(e)}


class TwitterMusicAPI:
    """Twitter API v2 integration for music buzz tracking."""

    def __init__(self, bearer_token: str):
        self.bearer_token = bearer_token
        self.base_url = "https://api.twitter.com/2"

    async def search_music_tweets(self, query: str, max_results: int = 100) -> list[dict[str, Any]]:
        """Search for music-related tweets."""
        endpoint = f"{self.base_url}/tweets/search/recent"

        params = {
            "query": f"{query} (music OR song OR artist OR album) -is:retweet",
            "max_results": max_results,
            "tweet.fields": "created_at,public_metrics,context_annotations,lang",
            "expansions": "author_id,geo.place_id",
            "user.fields": "public_metrics,verified,location",
        }

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.bearer_token}"}
                async with session.get(endpoint, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", [])
                    else:
                        print(f"Twitter API error: {response.status}")
                        return []
        except Exception as e:
            print(f"Twitter API exception: {e}")
            return []

    async def get_trending_music_hashtags(self, location_id: int = 1) -> list[dict[str, Any]]:
        """Get trending hashtags related to music."""
        endpoint = f"{self.base_url}/trends/place"

        params = {"id": location_id}  # 1 = Worldwide, 23424977 = US

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.bearer_token}"}
                async with session.get(endpoint, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        trends = data[0].get("trends", []) if data else []
                        # Filter for music-related trends
                        music_trends = [
                            trend
                            for trend in trends
                            if any(
                                keyword in trend["name"].lower()
                                for keyword in [
                                    "music",
                                    "song",
                                    "album",
                                    "artist",
                                    "#np",
                                    "#nowplaying",
                                ]
                            )
                        ]
                        return music_trends
                    else:
                        return []
        except Exception as e:
            print(f"Twitter trends error: {e}")
            return []


class InstagramMusicAPI:
    """Instagram Basic Display API integration."""

    def __init__(self, access_token: str):
        self.access_token = access_token
        self.base_url = "https://graph.instagram.com"

    async def get_music_hashtag_posts(self, hashtag: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get posts from music-related hashtags."""
        # Note: This would require Instagram Graph API access
        # For now, returning mock structure
        return []

    async def analyze_story_music_usage(self, user_id: str) -> dict[str, Any]:
        """Analyze music sticker usage in Stories."""
        # Note: This requires special permissions
        return {}


class SocialMusicDiscoveryEngine:
    """Main engine that coordinates all social media APIs for music discovery."""

    def __init__(self, config: dict[str, str]):
        """Initialize with API credentials."""
        self.config = config

        # Initialize API clients
        self.tiktok_api = None
        self.youtube_api = None
        self.twitter_api = None
        self.instagram_api = None

        if "tiktok_api_key" in config:
            self.tiktok_api = TikTokMusicAPI(
                config["tiktok_api_key"], config.get("tiktok_secret", "")
            )

        if "youtube_api_key" in config:
            self.youtube_api = YouTubeMusicAPI(config["youtube_api_key"])

        if "twitter_bearer_token" in config:
            self.twitter_api = TwitterMusicAPI(config["twitter_bearer_token"])

        if "instagram_access_token" in config:
            self.instagram_api = InstagramMusicAPI(config["instagram_access_token"])

        # Initialize trending schema for tracking
        self.trending_schema = TrendingSchema()

        # Storage for cross-platform trends
        self.cross_platform_trends: dict[str, CrossPlatformTrend] = {}

    async def discover_emerging_music(
        self, region: str = "US"
    ) -> dict[str, list[SocialMusicMetrics]]:
        """Discover emerging music across all platforms."""
        results = {}

        # TikTok discovery
        if self.tiktok_api:
            print("🎵 Discovering trending music on TikTok...")
            tiktok_sounds = await self.tiktok_api.get_trending_sounds(region)
            results[Platform.TIKTOK.value] = self._process_tiktok_data(tiktok_sounds)

        # YouTube discovery
        if self.youtube_api:
            print("🎥 Discovering trending music on YouTube...")
            youtube_videos = await self.youtube_api.get_trending_music_videos(region)
            results[Platform.YOUTUBE.value] = self._process_youtube_data(youtube_videos)

        # Twitter discovery
        if self.twitter_api:
            print("🐦 Discovering music buzz on Twitter...")
            music_tweets = await self.twitter_api.search_music_tweets("trending music", 100)
            results[Platform.TWITTER.value] = self._process_twitter_data(music_tweets)

        return results

    def _process_tiktok_data(self, tiktok_sounds: list[dict[str, Any]]) -> list[SocialMusicMetrics]:
        """Process TikTok trending sounds data."""
        processed = []

        for sound in tiktok_sounds:
            metrics = SocialMusicMetrics(
                platform=Platform.TIKTOK,
                song_id=sound.get("music_id", ""),
                artist_name=sound.get("artist", "Unknown"),
                song_title=sound.get("title", "Unknown"),
                video_uses=sound.get("video_count", 0),
                views=sound.get("play_count", 0),
                trend_velocity=sound.get("trend_score", 0.0),
                primary_age_group="13-24",  # TikTok's primary demographic
            )

            # Determine viral stage based on video count
            if metrics.video_uses > 1000000:
                metrics.viral_stage = ViralStage.MAINSTREAM
            elif metrics.video_uses > 100000:
                metrics.viral_stage = ViralStage.PLATFORM_VIRAL
            elif metrics.video_uses > 10000:
                metrics.viral_stage = ViralStage.NICHE_VIRAL
            else:
                metrics.viral_stage = ViralStage.EMERGING

            processed.append(metrics)

        return processed

    def _process_youtube_data(
        self, youtube_videos: list[dict[str, Any]]
    ) -> list[SocialMusicMetrics]:
        """Process YouTube trending music data."""
        processed = []

        for video in youtube_videos:
            snippet = video.get("snippet", {})
            statistics = video.get("statistics", {})

            metrics = SocialMusicMetrics(
                platform=Platform.YOUTUBE,
                song_id=video.get("id", ""),
                artist_name=self._extract_artist_from_title(snippet.get("title", "")),
                song_title=snippet.get("title", "Unknown"),
                views=int(statistics.get("viewCount", 0)),
                likes=int(statistics.get("likeCount", 0)),
                comments=int(statistics.get("commentCount", 0)),
                primary_age_group="16-24",  # YouTube Music's primary demographic
            )

            # Calculate trend velocity based on view-to-like ratio
            if metrics.views > 0:
                metrics.trend_velocity = metrics.likes / metrics.views

            # Determine viral stage
            if metrics.views > 10000000:
                metrics.viral_stage = ViralStage.MAINSTREAM
            elif metrics.views > 1000000:
                metrics.viral_stage = ViralStage.PLATFORM_VIRAL
            elif metrics.views > 100000:
                metrics.viral_stage = ViralStage.NICHE_VIRAL
            else:
                metrics.viral_stage = ViralStage.EMERGING

            processed.append(metrics)

        return processed

    def _process_twitter_data(self, tweets: list[dict[str, Any]]) -> list[SocialMusicMetrics]:
        """Process Twitter music buzz data."""
        processed = []

        # Group tweets by mentioned songs/artists
        song_mentions = {}

        for tweet in tweets:
            text = tweet.get("text", "").lower()
            public_metrics = tweet.get("public_metrics", {})

            # Simple keyword extraction (could be enhanced with NLP)
            song_keywords = self._extract_music_keywords(text)

            for keyword in song_keywords:
                if keyword not in song_mentions:
                    song_mentions[keyword] = {
                        "mentions": 0,
                        "total_likes": 0,
                        "total_retweets": 0,
                        "total_replies": 0,
                    }

                song_mentions[keyword]["mentions"] += 1
                song_mentions[keyword]["total_likes"] += public_metrics.get("like_count", 0)
                song_mentions[keyword]["total_retweets"] += public_metrics.get("retweet_count", 0)
                song_mentions[keyword]["total_replies"] += public_metrics.get("reply_count", 0)

        # Convert to SocialMusicMetrics
        for keyword, data in song_mentions.items():
            if data["mentions"] >= 3:  # Only include songs mentioned multiple times
                metrics = SocialMusicMetrics(
                    platform=Platform.TWITTER,
                    song_id=keyword,
                    artist_name="Unknown",
                    song_title=keyword,
                    hashtag_mentions=data["mentions"],
                    likes=data["total_likes"],
                    shares=data["total_retweets"],
                    comments=data["total_replies"],
                    primary_age_group="18-29",  # Twitter's primary demographic
                )

                # Calculate buzz score
                buzz_score = (
                    data["total_likes"] + data["total_retweets"] * 2 + data["total_replies"]
                ) / data["mentions"]
                metrics.trend_velocity = buzz_score

                # Determine viral stage based on mention frequency and engagement
                if data["mentions"] > 100:
                    metrics.viral_stage = ViralStage.PLATFORM_VIRAL
                elif data["mentions"] > 20:
                    metrics.viral_stage = ViralStage.NICHE_VIRAL
                else:
                    metrics.viral_stage = ViralStage.EMERGING

                processed.append(metrics)

        return processed

    def _extract_artist_from_title(self, title: str) -> str:
        """Extract artist name from video title."""
        # Simple extraction - could be enhanced with ML
        common_separators = [" - ", " | ", " by ", " feat. ", " ft. "]

        for sep in common_separators:
            if sep in title:
                return title.split(sep)[0].strip()

        return "Unknown"

    def _extract_music_keywords(self, text: str) -> list[str]:
        """Extract potential song/artist names from text."""
        # Simple keyword extraction - could be enhanced with NER
        music_indicators = ["song", "track", "album", "artist", "music", "#nowplaying", "#np"]

        keywords = []
        words = text.split()

        for i, word in enumerate(words):
            if (
                any(indicator in word.lower() for indicator in music_indicators)
                and i < len(words) - 1
            ):
                next_word = words[i + 1]
                if next_word.startswith('"') or next_word[0].isupper():
                    keywords.append(next_word.strip('"'))

        return keywords

    async def track_cross_platform_progression(self, song_id: str) -> CrossPlatformTrend:
        """Track how a song progresses across platforms."""
        if song_id in self.cross_platform_trends:
            return self.cross_platform_trends[song_id]

        # Initialize cross-platform tracking
        trend = CrossPlatformTrend(
            song_id=song_id,
            artist_name="Unknown",
            song_title="Unknown",
            origin_platform=Platform.TIKTOK,  # Default assumption
            current_platforms=[],
            viral_progression=[],
        )

        # Check presence on each platform
        platforms_found = []

        if self.tiktok_api:
            tiktok_data = await self.tiktok_api.get_sound_analytics(song_id)
            if "error" not in tiktok_data:
                platforms_found.append(Platform.TIKTOK)
                trend.viral_progression.append(
                    (Platform.TIKTOK, datetime.now(), ViralStage.PLATFORM_VIRAL)
                )

        if self.youtube_api:
            youtube_results = await self.youtube_api.search_music_by_keyword(song_id)
            if youtube_results:
                platforms_found.append(Platform.YOUTUBE)
                trend.viral_progression.append(
                    (Platform.YOUTUBE, datetime.now(), ViralStage.CROSS_PLATFORM)
                )

        trend.current_platforms = platforms_found

        # Predict mainstream breakthrough
        if len(platforms_found) >= 2:
            trend.predicted_mainstream_date = datetime.now() + timedelta(days=7)

        self.cross_platform_trends[song_id] = trend
        return trend

    async def generate_discovery_report(self, region: str = "US") -> dict[str, Any]:
        """Generate comprehensive music discovery report."""
        print("🔍 Generating comprehensive music discovery report...")

        # Discover music across platforms
        discoveries = await self.discover_emerging_music(region)

        # Analyze cross-platform presence
        cross_platform_analysis = {}
        all_songs = set()

        for platform, songs in discoveries.items():
            for song in songs:
                song_key = f"{song.artist_name} - {song.song_title}".lower()
                all_songs.add(song_key)

                if song_key not in cross_platform_analysis:
                    cross_platform_analysis[song_key] = {
                        "platforms": [],
                        "total_engagement": 0,
                        "viral_stages": [],
                    }

                cross_platform_analysis[song_key]["platforms"].append(platform)
                cross_platform_analysis[song_key]["total_engagement"] += (
                    song.views + song.likes + song.shares + song.video_uses
                )
                cross_platform_analysis[song_key]["viral_stages"].append(song.viral_stage.value)

        # Identify multi-platform hits
        multi_platform_hits = {
            song: data
            for song, data in cross_platform_analysis.items()
            if len(data["platforms"]) >= 2
        }

        # Generate insights
        insights = {
            "discovery_timestamp": datetime.now().isoformat(),
            "region": region,
            "total_songs_discovered": len(all_songs),
            "platform_discoveries": {
                platform: len(songs) for platform, songs in discoveries.items()
            },
            "multi_platform_hits": len(multi_platform_hits),
            "top_cross_platform_songs": sorted(
                multi_platform_hits.items(), key=lambda x: x[1]["total_engagement"], reverse=True
            )[:10],
            "viral_stage_distribution": self._analyze_viral_stages(discoveries),
            "age_group_preferences": self._analyze_age_preferences(discoveries),
            "platform_breakdown": discoveries,
            "recommendations": self._generate_recommendations(discoveries, multi_platform_hits),
        }

        return insights

    def _analyze_viral_stages(
        self, discoveries: dict[str, list[SocialMusicMetrics]]
    ) -> dict[str, int]:
        """Analyze distribution of viral stages across discoveries."""
        stage_counts: dict[str, int] = {}

        for _platform, songs in discoveries.items():
            for song in songs:
                stage = song.viral_stage.value
                stage_counts[stage] = stage_counts.get(stage, 0) + 1

        return stage_counts

    def _analyze_age_preferences(
        self, discoveries: dict[str, list[SocialMusicMetrics]]
    ) -> dict[str, list[str]]:
        """Analyze age group preferences across platforms."""
        age_preferences: dict[str, list[str]] = {}

        for _platform, songs in discoveries.items():
            for song in songs:
                age_group = song.primary_age_group
                if age_group not in age_preferences:
                    age_preferences[age_group] = []

                song_title = f"{song.artist_name} - {song.song_title}"
                if song_title not in age_preferences[age_group]:
                    age_preferences[age_group].append(song_title)

        return age_preferences

    def _generate_recommendations(
        self, discoveries: dict[str, list[SocialMusicMetrics]], multi_platform_hits: dict[str, Any]
    ) -> list[str]:
        """Generate actionable recommendations based on discoveries."""
        recommendations = []

        # Platform-specific recommendations
        platform_songs = {platform: len(songs) for platform, songs in discoveries.items()}

        if platform_songs.get(Platform.TIKTOK.value, 0) > platform_songs.get(
            Platform.YOUTUBE.value, 0
        ):
            recommendations.append(
                "TikTok is currently the primary discovery platform. Focus on TikTok-first content strategy."
            )

        # Multi-platform recommendations
        if len(multi_platform_hits) > 5:
            recommendations.append(
                f"Strong cross-platform activity detected ({len(multi_platform_hits)} multi-platform hits). "
                "Consider cross-platform promotion campaigns."
            )

        # Viral stage recommendations
        emerging_count = sum(
            1
            for songs in discoveries.values()
            for song in songs
            if song.viral_stage == ViralStage.EMERGING
        )

        if emerging_count > 10:
            recommendations.append(
                f"{emerging_count} emerging songs detected. Perfect time for early adoption and playlist placement."
            )

        return recommendations

    def save_discovery_report(self, report: dict[str, Any], filepath: str = None) -> str:
        """Save discovery report to file using centralized utility."""
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"data/social_discovery_report_{timestamp}.json"

        saved_path = write_json(filepath, report)
        return str(saved_path)


# Mock data generator for testing without API keys
def create_mock_discovery_data() -> SocialMusicDiscoveryEngine:
    """Create mock social discovery engine for testing."""
    config = {"mock_mode": True}

    engine = SocialMusicDiscoveryEngine(config)

    # Add mock data
    mock_tiktok_data = [
        {
            "music_id": "tt_001",
            "title": "Vampire",
            "artist": "Olivia Rodrigo",
            "video_count": 2500000,
            "play_count": 50000000,
            "trend_score": 0.95,
        },
        {
            "music_id": "tt_002",
            "title": "Anti-Hero",
            "artist": "Taylor Swift",
            "video_count": 1800000,
            "play_count": 35000000,
            "trend_score": 0.87,
        },
    ]

    mock_youtube_data = [
        {
            "id": "yt_001",
            "snippet": {"title": "Olivia Rodrigo - Vampire (Official Video)"},
            "statistics": {
                "viewCount": "125000000",
                "likeCount": "2500000",
                "commentCount": "180000",
            },
        }
    ]

    # Override methods for mock data
    async def mock_discover_emerging_music(region="US"):
        return {
            Platform.TIKTOK.value: engine._process_tiktok_data(mock_tiktok_data),
            Platform.YOUTUBE.value: engine._process_youtube_data(mock_youtube_data),
        }

    engine.discover_emerging_music = mock_discover_emerging_music

    return engine


if __name__ == "__main__":
    print("🎵 Social Media Music Discovery Engine")
    print("=" * 50)

    # Create mock engine for demonstration
    engine = create_mock_discovery_data()

    async def demo():
        print("🔍 Discovering emerging music trends...")

        # Generate discovery report
        report = await engine.generate_discovery_report()

        print("\n📊 Discovery Report Summary:")
        print(f"   Total songs discovered: {report['total_songs_discovered']}")
        print(f"   Multi-platform hits: {report['multi_platform_hits']}")

        print("\n📈 Platform Breakdown:")
        for platform, count in report["platform_discoveries"].items():
            print(f"   {platform}: {count} songs")

        print("\n🎯 Top Recommendations:")
        for i, rec in enumerate(report["recommendations"][:3], 1):
            print(f"   {i}. {rec}")

        # Save report
        filepath = engine.save_discovery_report(report)
        print(f"\n💾 Report saved to: {filepath}")

    # Run demo
    import asyncio

    asyncio.run(demo())

    print("\n🎯 Social discovery engine ready!")
    print("Next: Add your API keys to enable live data collection")
