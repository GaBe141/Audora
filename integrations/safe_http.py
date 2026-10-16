"""Outbound HTTP helpers that refuse redirects and environment proxies."""

import re
from typing import Any

import aiohttp
import requests

_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_API_KEY = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SUBREDDIT = re.compile(r"^[A-Za-z0-9_]{2,21}$")
_TUMBLR_BLOG = re.compile(r"^[A-Za-z0-9-]{1,32}$")
_DISCORD_GUILD = re.compile(r"^\d{5,32}$")
_CHART_COUNTRY = re.compile(r"^(?:global|[a-z]{2})$")
_CHART_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
REDDIT_TIME_FILTERS = frozenset({"hour", "day", "week", "month", "year", "all"})


def is_safe_path(path: str) -> bool:
    """Return True when path is a relative API path made of safe segments."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\")):
        return False
    if any(token in path for token in ("\\", "..", "://", "?", "#", "@")):
        return False
    parts = path.split("/")
    return all(bool(part) and _PATH_SEGMENT.fullmatch(part) is not None for part in parts)


def is_safe_api_key(value: str | None) -> bool:
    """Return True when an API key can be placed in a URL path."""
    return isinstance(value, str) and _API_KEY.fullmatch(value) is not None


def is_redirect_status(status_code: object) -> bool:
    """Return True for HTTP redirect statuses. Non-integers are not redirects."""
    return isinstance(status_code, int) and status_code in _REDIRECT_STATUSES


def safe_subreddit(value: object) -> str | None:
    """Return a subreddit name that cannot change the request path."""
    if isinstance(value, str) and _SUBREDDIT.fullmatch(value):
        return value
    return None


def safe_tumblr_blog(value: object) -> str | None:
    """Return a Tumblr blog name that cannot change the request path."""
    if isinstance(value, str) and _TUMBLR_BLOG.fullmatch(value):
        return value
    return None


def safe_discord_guild(value: object) -> str | None:
    """Return a numeric Discord guild id."""
    if isinstance(value, str) and _DISCORD_GUILD.fullmatch(value):
        return value
    return None


def safe_chart_country(value: object) -> str | None:
    """Return a Spotify chart country code or 'global'."""
    if not isinstance(value, str):
        return None
    country = value.strip().lower()
    if _CHART_COUNTRY.fullmatch(country):
        return country
    return None


def safe_chart_date(value: object) -> str | None:
    """Return a YYYY-MM-DD chart date."""
    if isinstance(value, str) and _CHART_DATE.fullmatch(value):
        return value
    return None


class NoRedirectRequests(requests.Session):
    """requests session that ignores proxy environment variables and never follows redirects."""

    def __init__(self) -> None:
        super().__init__()
        self.trust_env = False

    def request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        kwargs["allow_redirects"] = False
        return super().request(method, url, *args, **kwargs)


class NoRedirectSession:
    """aiohttp session wrapper that ignores proxy env vars and never follows redirects.

    This is not a ClientSession subclass: aiohttp 3.14 deprecates subclassing ClientSession.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["trust_env"] = False
        self._session = aiohttp.ClientSession(*args, **kwargs)

    async def __aenter__(self) -> "NoRedirectSession":
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self._session.__aexit__(exc_type, exc, tb)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)
