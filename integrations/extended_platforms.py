"""
Extended platform integrations for Reddit, Tumblr, and other social APIs.
Specialized for Gen Z/Alpha music discovery patterns.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from social_discovery_engine import Platform, SocialMusicMetrics, ViralStage

REQUEST_TIMEOUT_SECONDS = 15


class RedditMusicAPI:
    """Reddit API integration for music community discovery."""

    def __init__(
        self, client_id: str, client_secret: str, user_agent: str = "MusicDiscoveryBot/1.0"
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_agent = user_agent
        self.base_url = "https://oauth.reddit.com"
        self.access_token = None
        self.token_expires = None

    async def authenticate(self):
        """Get OAuth token for Reddit API."""
        auth_url = "https://www.reddit.com/api/v1/access_token"

        auth = aiohttp.BasicAuth(self.client_id, self.client_secret)
        headers = {"User-Agent": self.user_agent}
        data = {"grant_type": "client_credentials"}

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    auth_url, auth=auth, headers=headers, data=data
                ) as response:
                    if response.status == 200:
                        token_data = await response.json()
                        self.access_token = token_data["access_token"]
                        self.token_expires = datetime.now() + timedelta(
                            seconds=token_data["expires_in"]
                        )
                        return True
                    else:
                        print(f"Reddit auth failed: {response.status}")
                        return False
        except Exception as e:
            print(f"Reddit auth error: {e}")
            return False

    async def get_music_subreddit_posts(
        self, subreddit: str, limit: int = 100, time_filter: str = "day"
    ) -> list[dict[str, Any]]:
        """Get posts from music-related subreddits."""
        if not self.access_token or datetime.now() >= self.token_expires:
            await self.authenticate()

        endpoint = f"{self.base_url}/r/{subreddit}/hot"
        headers = {"Authorization": f"Bearer {self.access_token}", "User-Agent": self.user_agent}
        params = {"limit": limit, "t": time_filter}

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", {}).get("children", [])
                    else:
                        print(f"Reddit API error: {response.status}")
                        return []
        except Exception as e:
            print(f"Reddit API exception: {e}")
            return []

    async def search_music_discussions(
        self, query: str, subreddits: list[str] = None
    ) -> list[dict[str, Any]]:
        """Search for music discussions across subreddits."""
        if subreddits is None:
            subreddits = [
                "Music",
                "hiphopheads",
                "popheads",
                "indieheads",
                "electronicmusic",
                "WeAreTheMusicMakers",
                "listentothis",
                "ifyoulikeblank",
            ]

        if not self.access_token or datetime.now() >= self.token_expires:
            await self.authenticate()

        all_results = []

        for subreddit in subreddits:
            endpoint = f"{self.base_url}/r/{subreddit}/search"
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": self.user_agent,
            }
            params = {"q": query, "sort": "relevance", "restrict_sr": "true", "limit": 25}

            try:
                timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(endpoint, headers=headers, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            posts = data.get("data", {}).get("children", [])
                            for post in posts:
                                post["subreddit_source"] = subreddit
                            all_results.extend(posts)
            except Exception as e:
                print(f"Reddit search error for {subreddit}: {e}")
                continue

        return all_results

    async def get_trending_music_topics(self) -> list[dict[str, Any]]:
        """Get trending music topics across all music subreddits."""
        music_subreddits = [
            "Music",
            "hiphopheads",
            "popheads",
            "indieheads",
            "electronicmusic",
            "WeAreTheMusicMakers",
            "listentothis",
            "ifyoulikeblank",
            "metal",
            "punk",
            "jazz",
            "classicalmusic",
            "folk",
            "country",
            "rap",
        ]

        trending_topics = []

        for subreddit in music_subreddits:
            posts = await self.get_music_subreddit_posts(subreddit, limit=50)

            for post_data in posts:
                post = post_data.get("data", {})

                # Filter for music-related posts
                if self._is_music_related_post(post):
                    trending_topics.append(
                        {
                            "subreddit": subreddit,
                            "title": post.get("title", ""),
                            "score": post.get("score", 0),
                            "num_comments": post.get("num_comments", 0),
                            "created_utc": post.get("created_utc", 0),
                            "url": post.get("url", ""),
                            "selftext": post.get("selftext", ""),
                            "upvote_ratio": post.get("upvote_ratio", 0),
                        }
                    )

        # Sort by engagement score
        trending_topics.sort(key=lambda x: x["score"] + x["num_comments"], reverse=True)

        return trending_topics[:100]

    def _is_music_related_post(self, post: dict[str, Any]) -> bool:
        """Check if a post is music-related."""
        title = post.get("title", "").lower()
        selftext = post.get("selftext", "").lower()

        music_keywords = [
            "song",
            "album",
            "artist",
            "band",
            "music",
            "track",
            "single",
            "release",
            "debut",
            "new music",
            "listen",
            "streaming",
            "playlist",
        ]

        return any(keyword in title or keyword in selftext for keyword in music_keywords)


class TumblrMusicAPI:
    """Tumblr API integration for music culture and aesthetics."""

    def __init__(self, consumer_key: str, consumer_secret: str):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.base_url = "https://api.tumblr.com/v2"

    async def search_music_posts(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Search for music-related posts on Tumblr."""
        endpoint = f"{self.base_url}/tagged"

        params = {"tag": query, "api_key": self.consumer_key, "limit": limit}

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("response", [])
                    else:
                        print(f"Tumblr API error: {response.status}")
                        return []
        except Exception as e:
            print(f"Tumblr API exception: {e}")
            return []

    async def get_music_blog_posts(self, blog_name: str, limit: int = 20) -> list[dict[str, Any]]:
        """Get posts from a specific music blog."""
        endpoint = f"{self.base_url}/blog/{blog_name}/posts"

        params = {
            "api_key": self.consumer_key,
            "limit": limit,
            "type": "audio",  # Focus on audio posts
        }

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("response", {}).get("posts", [])
                    else:
                        return []
        except Exception as e:
            print(f"Tumblr blog error: {e}")
            return []

    async def discover_music_aesthetics(self) -> list[dict[str, Any]]:
        """Discover music-related aesthetic trends on Tumblr."""
        aesthetic_tags = [
            "dark academia music",
            "indie aesthetic",
            "cottagecore music",
            "y2k music",
            "vaporwave",
            "lo-fi aesthetic",
            "grunge music",
            "soft girl music",
            "dark feminine music",
            "alt music aesthetic",
        ]

        aesthetic_trends = []

        for tag in aesthetic_tags:
            posts = await self.search_music_posts(tag, limit=20)

            for post in posts:
                if post.get("type") in ["audio", "text", "photo"]:
                    aesthetic_trends.append(
                        {
                            "tag": tag,
                            "post_type": post.get("type"),
                            "note_count": post.get("note_count", 0),
                            "timestamp": post.get("timestamp"),
                            "tags": post.get("tags", []),
                            "summary": post.get("summary", ""),
                            "blog_name": post.get("blog_name", ""),
                        }
                    )

        # Sort by note count (engagement)
        aesthetic_trends.sort(key=lambda x: x["note_count"], reverse=True)

        return aesthetic_trends


class SoundCloudAPI:
    """SoundCloud API integration for emerging artist discovery."""

    def __init__(self, client_id: str):
        self.client_id = client_id
        self.base_url = "https://api.soundcloud.com"

    async def get_trending_tracks(self, genre: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Get trending tracks from SoundCloud."""
        endpoint = f"{self.base_url}/tracks"

        params = {"client_id": self.client_id, "limit": limit, "order": "hotness"}

        if genre:
            params["genres"] = genre

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        print(f"SoundCloud API error: {response.status}")
                        return []
        except Exception as e:
            print(f"SoundCloud API exception: {e}")
            return []

    async def search_emerging_artists(
        self, query: str = "", min_followers: int = 1000, max_followers: int = 50000
    ) -> list[dict[str, Any]]:
        """Find emerging artists in the sweet spot of followers."""
        endpoint = f"{self.base_url}/users"

        params = {"client_id": self.client_id, "q": query, "limit": 50}

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, params=params) as response:
                    if response.status == 200:
                        users = await response.json()

                        # Filter by follower count
                        emerging_artists = [
                            user
                            for user in users
                            if min_followers <= user.get("followers_count", 0) <= max_followers
                        ]

                        return emerging_artists
                    else:
                        return []
        except Exception as e:
            print(f"SoundCloud search error: {e}")
            return []


class DiscordMusicBot:
    """Discord bot integration for music community analysis."""

    def __init__(self, bot_token: str):
        self.bot_token = bot_token
        self.base_url = "https://discord.com/api/v10"

    async def get_guild_voice_activity(self, guild_id: str) -> dict[str, Any]:
        """Get voice channel activity for music listening patterns."""
        # Note: This requires special Discord bot permissions
        endpoint = f"{self.base_url}/guilds/{guild_id}/voice-states"

        headers = {"Authorization": f"Bot {self.bot_token}"}

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {}
        except Exception as e:
            print(f"Discord API error: {e}")
            return {}


class ExtendedSocialDiscoveryEngine:
    """Extended discovery engine with additional platform integrations."""

    def __init__(self, api_configs: dict[str, dict[str, str]]):
        """Initialize with extended API configurations."""
        self.reddit_api = None
        self.tumblr_api = None
        self.soundcloud_api = None
        self.discord_bot = None

        # Initialize APIs based on available configs
        if "reddit" in api_configs:
            config = api_configs["reddit"]
            if config.get("client_id") and config.get("client_secret"):
                self.reddit_api = RedditMusicAPI(config["client_id"], config["client_secret"])

        if "tumblr" in api_configs:
            config = api_configs["tumblr"]
            if config.get("consumer_key"):
                self.tumblr_api = TumblrMusicAPI(
                    config["consumer_key"], config.get("consumer_secret", "")
                )

        if "soundcloud" in api_configs:
            config = api_configs["soundcloud"]
            if config.get("client_id"):
                self.soundcloud_api = SoundCloudAPI(config["client_id"])

        if "discord" in api_configs:
            config = api_configs["discord"]
            if config.get("bot_token"):
                self.discord_bot = DiscordMusicBot(config["bot_token"])

    async def discover_underground_music(self) -> dict[str, list[SocialMusicMetrics]]:
        """Discover underground and emerging music across platforms."""
        results = {}

        # Reddit discovery
        if self.reddit_api:
            print("🤖 Discovering music discussions on Reddit...")
            reddit_data = await self.reddit_api.get_trending_music_topics()
            results[Platform.REDDIT.value] = self._process_reddit_data(reddit_data)

        # Tumblr discovery
        if self.tumblr_api:
            print("📝 Discovering music aesthetics on Tumblr...")
            tumblr_data = await self.tumblr_api.discover_music_aesthetics()
            results[Platform.TUMBLR.value] = self._process_tumblr_data(tumblr_data)

        # SoundCloud discovery
        if self.soundcloud_api:
            print("🎵 Discovering emerging artists on SoundCloud...")
            soundcloud_data = await self.soundcloud_api.get_trending_tracks()
            results[Platform.SOUNDCLOUD.value] = self._process_soundcloud_data(soundcloud_data)

        return results

    def _process_reddit_data(self, reddit_posts: list[dict[str, Any]]) -> list[SocialMusicMetrics]:
        """Process Reddit music discussion data."""
        processed = []

        for post in reddit_posts[:50]:  # Limit to top 50 posts
            # Extract potential song/artist info from title
            title = post.get("title", "")
            artist_name, song_title = self._extract_music_info_from_text(title)

            metrics = SocialMusicMetrics(
                platform=Platform.REDDIT,
                song_id=f"reddit_{post.get('subreddit', '')}_{title[:50]}",
                artist_name=artist_name,
                song_title=song_title,
                likes=post.get("score", 0),
                comments=post.get("num_comments", 0),
                primary_age_group="16-25",  # Reddit's music community demographic
            )

            # Calculate engagement score
            engagement_score = post.get("score", 0) + (post.get("num_comments", 0) * 2)
            metrics.trend_velocity = engagement_score

            # Determine viral stage based on engagement
            if engagement_score > 1000:
                metrics.viral_stage = ViralStage.PLATFORM_VIRAL
            elif engagement_score > 100:
                metrics.viral_stage = ViralStage.NICHE_VIRAL
            else:
                metrics.viral_stage = ViralStage.EMERGING

            processed.append(metrics)

        return processed

    def _process_tumblr_data(self, tumblr_posts: list[dict[str, Any]]) -> list[SocialMusicMetrics]:
        """Process Tumblr aesthetic and music data."""
        processed = []

        for post in tumblr_posts[:30]:  # Limit to top 30 posts
            tag = post.get("tag", "")
            artist_name, song_title = self._extract_music_info_from_text(tag)

            metrics = SocialMusicMetrics(
                platform=Platform.TUMBLR,
                song_id=f"tumblr_{tag}",
                artist_name=artist_name,
                song_title=song_title or tag,
                likes=post.get("note_count", 0),
                hashtag_mentions=len(post.get("tags", [])),
                primary_age_group="16-24",  # Tumblr's primary demographic
            )

            # Tumblr note count as engagement metric
            metrics.trend_velocity = post.get("note_count", 0) / 100  # Normalize

            # Viral stage based on note count
            note_count = post.get("note_count", 0)
            if note_count > 10000:
                metrics.viral_stage = ViralStage.PLATFORM_VIRAL
            elif note_count > 1000:
                metrics.viral_stage = ViralStage.NICHE_VIRAL
            else:
                metrics.viral_stage = ViralStage.EMERGING

            processed.append(metrics)

        return processed

    def _process_soundcloud_data(
        self, soundcloud_tracks: list[dict[str, Any]]
    ) -> list[SocialMusicMetrics]:
        """Process SoundCloud trending tracks."""
        processed = []

        for track in soundcloud_tracks[:40]:  # Limit to top 40 tracks
            user_info = track.get("user", {})

            metrics = SocialMusicMetrics(
                platform=Platform.SOUNDCLOUD,
                song_id=str(track.get("id", "")),
                artist_name=user_info.get("username", "Unknown"),
                song_title=track.get("title", "Unknown"),
                views=track.get("playback_count", 0),
                likes=track.get("likes_count", 0),
                shares=track.get("reposts_count", 0),
                comments=track.get("comment_count", 0),
                primary_age_group="18-26",  # SoundCloud's demographic
            )

            # Calculate viral score based on engagement
            viral_score = metrics.views + metrics.likes * 10 + metrics.shares * 5
            metrics.trend_velocity = viral_score / 10000  # Normalize

            # Determine viral stage
            if viral_score > 500000:
                metrics.viral_stage = ViralStage.PLATFORM_VIRAL
            elif viral_score > 50000:
                metrics.viral_stage = ViralStage.NICHE_VIRAL
            else:
                metrics.viral_stage = ViralStage.EMERGING

            processed.append(metrics)

        return processed

    def _extract_music_info_from_text(self, text: str) -> tuple[str, str]:
        """Extract artist and song names from text."""
        # Simple extraction logic - could be enhanced with NLP
        text = text.strip()

        # Common patterns: "Artist - Song", "Artist: Song", "Song by Artist"
        separators = [" - ", ": ", " by ", " | "]

        for sep in separators:
            if sep in text:
                parts = text.split(sep, 1)
                if len(parts) == 2:
                    return parts[0].strip(), parts[1].strip()

        # If no pattern found, assume it's a song title
        return "Unknown", text

    async def generate_comprehensive_report(self) -> dict[str, Any]:
        """Generate comprehensive discovery report including underground platforms."""
        print("🔍 Generating comprehensive multi-platform discovery report...")

        # Get underground discoveries
        underground_discoveries = await self.discover_underground_music()

        # Calculate insights
        total_underground_songs = sum(len(songs) for songs in underground_discoveries.values())

        # Platform analysis
        platform_strengths = {}
        for platform, songs in underground_discoveries.items():
            if songs:
                avg_engagement = sum(song.trend_velocity for song in songs) / len(songs)
                platform_strengths[platform] = {
                    "song_count": len(songs),
                    "avg_engagement": avg_engagement,
                    "top_viral_stage": (
                        max(song.viral_stage.value for song in songs) if songs else "unknown"
                    ),
                }

        # Generate recommendations
        recommendations = []

        if "reddit" in underground_discoveries and len(underground_discoveries["reddit"]) > 10:
            recommendations.append(
                "Strong Reddit music community activity detected. Consider engaging with "
                "music subreddits for grassroots promotion."
            )

        if "tumblr" in underground_discoveries and len(underground_discoveries["tumblr"]) > 5:
            recommendations.append(
                "Active Tumblr music aesthetic trends found. Visual branding and "
                "aesthetic content could be effective."
            )

        if "soundcloud" in underground_discoveries:
            emerging_count = sum(
                1
                for song in underground_discoveries["soundcloud"]
                if song.viral_stage == ViralStage.EMERGING
            )
            if emerging_count > 5:
                recommendations.append(
                    f"{emerging_count} emerging SoundCloud artists detected. "
                    "Perfect time for early collaboration or playlist placement."
                )

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_underground_songs": total_underground_songs,
            "platform_discoveries": {
                platform: len(songs) for platform, songs in underground_discoveries.items()
            },
            "platform_strengths": platform_strengths,
            "underground_breakdown": underground_discoveries,
            "recommendations": recommendations,
            "next_steps": [
                "Monitor trending topics across underground platforms",
                "Engage with emerging communities before mainstream adoption",
                "Track aesthetic trends for visual content strategy",
                "Identify collaboration opportunities with emerging artists",
            ],
        }

        return report


# Example usage and testing
async def demo_extended_discovery():
    """Demonstrate extended discovery capabilities."""
    # Mock configuration for testing
    mock_configs = {
        "reddit": {"client_id": "mock_reddit_id", "client_secret": "mock_reddit_secret"},
        "tumblr": {"consumer_key": "mock_tumblr_key"},
        "soundcloud": {"client_id": "mock_soundcloud_id"},
    }

    engine = ExtendedSocialDiscoveryEngine(mock_configs)

    # Mock data for demonstration
    mock_reddit_data = [
        {
            "title": "Olivia Rodrigo - vampire is actually incredible",
            "score": 2500,
            "num_comments": 342,
            "subreddit": "popheads",
        },
        {
            "title": "Ice Spice: The Rise of Bronx Drill Princess",
            "score": 1800,
            "num_comments": 456,
            "subreddit": "hiphopheads",
        },
    ]

    # Process mock data
    reddit_metrics = engine._process_reddit_data(mock_reddit_data)

    print("🎯 Extended Discovery Demo Results:")
    print(f"   Reddit discoveries: {len(reddit_metrics)}")

    for metric in reddit_metrics:
        print(f"   📊 {metric.artist_name} - {metric.song_title}")
        print(f"      Platform: {metric.platform.value}")
        print(f"      Engagement: {metric.trend_velocity:.0f}")
        print(f"      Viral Stage: {metric.viral_stage.value}")


if __name__ == "__main__":
    print("🎵 Extended Social Discovery Engine")
    print("=" * 50)

    # Run demonstration
    asyncio.run(demo_extended_discovery())

    print("\n🎯 Extended discovery system ready!")
    print("Add your API credentials to start discovering underground music trends")
