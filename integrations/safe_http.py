"""HTTP session wrapper that refuses redirects and environment proxies."""

from typing import Any

import aiohttp


class NoRedirectSession:
    """aiohttp session wrapper that ignores proxy env vars and disables redirects.

    This is intentionally not a ClientSession subclass. aiohttp deprecates
    subclassing ClientSession, and a wrapper keeps redirect policy in one place.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["trust_env"] = False
        self._session = aiohttp.ClientSession(*args, **kwargs)

    async def __aenter__(self) -> "NoRedirectSession":
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self._session.__aexit__(exc_type, exc, tb)

    def get(self, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.post(url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.request(method, url, **kwargs)
