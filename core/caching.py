"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import base64
import hashlib
import hmac
import io
import json
import logging
import os
import time
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any, ParamSpec, TypeVar

import pandas as pd

logger = logging.getLogger(__name__)

# Try to import Redis, fall back to local cache if unavailable
try:
    import redis
    from redis import ConnectionPool

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available, using local cache fallback")

P = ParamSpec("P")
R = TypeVar("R")

_MAX_CACHE_BYTES = 8 * 1024 * 1024
_TYPE_TAG = "__audora_type__"
_TAGGED_TYPES = frozenset({"datetime", "tuple", "dataframe"})


def _to_jsonable(value: Any) -> Any:
    """Convert a cache value to JSON-safe data without executing it."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return {_TYPE_TAG: "datetime", "value": value.isoformat()}
    if isinstance(value, tuple):
        return {_TYPE_TAG: "tuple", "value": [_to_jsonable(item) for item in value]}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, pd.DataFrame):
        return {
            _TYPE_TAG: "dataframe",
            "value": value.to_json(orient="split", date_format="iso"),
        }
    if isinstance(value, pd.Timestamp):
        return {_TYPE_TAG: "datetime", "value": value.isoformat()}
    item = getattr(value, "item", None)
    if callable(item):
        try:
            converted = item()
        except (ValueError, TypeError):
            converted = value
        if converted is not value:
            return _to_jsonable(converted)
    raise TypeError(f"Unsupported cache value type: {type(value).__name__}")


def _from_jsonable(value: Any) -> Any:
    """Restore JSON-safe cache data. Unknown type tags are rejected."""
    if isinstance(value, list):
        return [_from_jsonable(item) for item in value]
    if isinstance(value, dict):
        marker = value.get(_TYPE_TAG)
        if set(value) == {_TYPE_TAG, "value"} and marker in _TAGGED_TYPES:
            payload = value.get("value")
            if marker == "datetime" and isinstance(payload, str):
                return datetime.fromisoformat(payload)
            if marker == "tuple" and isinstance(payload, list):
                return tuple(_from_jsonable(item) for item in payload)
            if marker == "dataframe" and isinstance(payload, str):
                return pd.read_json(io.StringIO(payload), orient="split")
            raise ValueError("Rejected cache entry with an invalid type tag")
        if marker is not None and set(value) == {_TYPE_TAG, "value"}:
            raise ValueError("Rejected cache entry with an unsupported type tag")
        return {key: _from_jsonable(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("Rejected cache entry with an unsupported JSON value")


def dumps_signed(value: Any, signing_key: bytes) -> bytes:
    """Serialize a cache value as HMAC-signed JSON."""
    encoded = json.dumps(
        _to_jsonable(value),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(encoded) > _MAX_CACHE_BYTES:
        raise ValueError("Cache payload exceeds size limit")
    signature = hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()
    envelope = {
        "v": 2,
        "alg": "HMAC-SHA256",
        "sig": signature,
        "payload": base64.b64encode(encoded).decode("ascii"),
    }
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if len(raw) > _MAX_CACHE_BYTES:
        raise ValueError("Cache payload exceeds size limit")
    return raw


def loads_signed(raw: bytes | bytearray, signing_key: bytes) -> Any:
    """Load a signed JSON cache value. Pickle and unsigned bytes are rejected."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("Cache payload must be bytes")
    if len(raw) > _MAX_CACHE_BYTES:
        raise ValueError("Cache payload exceeds size limit")
    stripped = bytes(raw).lstrip()
    if not stripped.startswith(b"{"):
        raise ValueError("Rejected pickle or unsigned cache payload")
    try:
        envelope = json.loads(stripped.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Rejected unsigned cache payload") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("v") != 2
        or envelope.get("alg") != "HMAC-SHA256"
        or not isinstance(envelope.get("sig"), str)
        or not isinstance(envelope.get("payload"), str)
    ):
        raise ValueError("Rejected cache entry with invalid serialization envelope")
    try:
        payload = base64.b64decode(envelope["payload"].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Rejected cache entry with an invalid payload") from exc
    if len(payload) > _MAX_CACHE_BYTES:
        raise ValueError("Cache payload exceeds size limit")
    expected_sig = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope["sig"], expected_sig):
        raise ValueError("Rejected cache entry with invalid signature")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Rejected cache entry with invalid JSON") from exc
    return _from_jsonable(decoded)


class CacheBackend:
    """Base cache backend interface."""

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache with optional TTL."""
        raise NotImplementedError

    def delete(self, key: str) -> None:
        """Delete value from cache."""
        raise NotImplementedError

    def clear(self) -> None:
        """Clear all cached values."""
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        raise NotImplementedError


class LocalCacheBackend(CacheBackend):
    """In-memory cache backend with TTL support.

    Uses dictionary for storage with automatic expiration.
    """

    def __init__(self, max_size: int = 1000) -> None:
        """Initialize local cache.

        Args:
            max_size: Maximum number of items to cache (LRU eviction)
        """
        self._cache: dict[str, dict[str, Any]] = {}
        self._max_size = max_size
        self._access_times: dict[str, float] = {}
        logger.info(f"Local cache initialized (max_size={max_size})")

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        if key not in self._cache:
            return None

        entry = self._cache[key]
        expiry = entry.get("expiry")

        # Check if expired
        if expiry and time.time() > expiry:
            del self._cache[key]
            if key in self._access_times:
                del self._access_times[key]
            return None

        # Update access time for LRU
        self._access_times[key] = time.time()
        return entry["value"]

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache with optional TTL."""
        # Evict if cache is full
        if len(self._cache) >= self._max_size and key not in self._cache:
            self._evict_lru()

        expiry = time.time() + ttl if ttl else None
        self._cache[key] = {"value": value, "expiry": expiry}
        self._access_times[key] = time.time()

    def delete(self, key: str) -> None:
        """Delete value from cache."""
        if key in self._cache:
            del self._cache[key]
        if key in self._access_times:
            del self._access_times[key]

    def clear(self) -> None:
        """Clear all cached values."""
        count = len(self._cache)
        self._cache.clear()
        self._access_times.clear()
        logger.debug(f"Cleared {count} items from local cache")

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        return self.get(key) is not None

    def _evict_lru(self) -> None:
        """Evict least recently used item."""
        if not self._access_times:
            return

        lru_key = min(self._access_times.items(), key=lambda x: x[1])[0]
        self.delete(lru_key)
        logger.debug(f"Evicted LRU cache entry: {lru_key}")


class RedisCacheBackend(CacheBackend):
    """Redis cache backend with connection pooling."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        max_connections: int = 10,
        key_prefix: str = "audora",
    ) -> None:
        """Initialize Redis cache.

        Args:
            host: Redis server host
            port: Redis server port
            db: Redis database number
            password: Redis password (if required)
            max_connections: Maximum connections in pool
            key_prefix: Namespace deleted by clear(); other Redis keys are left intact
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis package not installed")
        if any(char in key_prefix for char in "*?[]"):
            raise ValueError("Cache key prefix must not contain glob characters")

        self._key_prefix = key_prefix
        self._pool = ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=False,  # Keep binary mode for signed payloads
        )
        self._client = redis.Redis(connection_pool=self._pool)
        self._signing_key = self._get_signing_key()

        # Test connection
        try:
            self._client.ping()
            logger.info(f"Redis cache connected to {host}:{port}/{db}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _get_signing_key(self) -> bytes:
        """Get cache signing key used to verify serialized payload integrity."""
        configured_key = os.getenv("AUDORA_CACHE_SIGNING_KEY", "").strip()
        configured = configured_key.encode("utf-8")
        if len(configured) >= 16:
            return configured

        if configured_key:
            logger.warning(
                "AUDORA_CACHE_SIGNING_KEY is too short; using a process-local signing key"
            )
        else:
            logger.warning(
                "AUDORA_CACHE_SIGNING_KEY is not set; using a process-local signing key. "
                "Set AUDORA_CACHE_SIGNING_KEY for a shared Redis cache across processes."
            )
        return os.urandom(32)

    def _serialize(self, value: Any) -> bytes:
        """Serialize cache value as signed JSON."""
        return dumps_signed(value, self._signing_key)

    def _deserialize(self, value: bytes) -> Any:
        """Deserialize a signed JSON cache value."""
        return loads_signed(value, self._signing_key)

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            value = self._client.get(key)
            if value is None:
                return None
            return self._deserialize(value)
        except ValueError as e:
            logger.warning("Rejected cache entry for key %s: %s", key, e)
            try:
                self._client.delete(key)
            except Exception as delete_error:
                logger.error("Redis delete of rejected key %s failed: %s", key, delete_error)
            return None
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache with optional TTL."""
        try:
            serialized = self._serialize(value)
            if ttl:
                self._client.setex(key, ttl, serialized)
            else:
                self._client.set(key, serialized)
        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")

    def delete(self, key: str) -> None:
        """Delete value from cache."""
        try:
            self._client.delete(key)
        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {e}")

    def clear(self) -> None:
        """Delete keys in this cache namespace without flushing the Redis database."""
        try:
            match = f"{self._key_prefix}:*"
            cursor = 0
            deleted = 0
            while True:
                cursor, keys = self._client.scan(cursor=cursor, match=match, count=200)
                if keys:
                    deleted += int(self._client.delete(*keys))
                if cursor in (0, "0", b"0"):
                    break
            logger.debug("Cleared %s Redis keys under %s", deleted, self._key_prefix)
        except Exception as e:
            logger.error(f"Redis clear error: {e}")

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        try:
            return bool(self._client.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error for key {key}: {e}")
            return False


class CacheManager:
    """High-level cache manager with automatic backend selection.

    Automatically uses Redis if available, falls back to local cache.
    """

    def __init__(
        self,
        backend: CacheBackend | None = None,
        default_ttl: int = 3600,
        key_prefix: str = "audora",
    ) -> None:
        """Initialize cache manager.

        Args:
            backend: Custom cache backend (auto-detected if None)
            default_ttl: Default TTL in seconds (1 hour default)
            key_prefix: Prefix for all cache keys
        """
        if any(char in key_prefix for char in "*?[]"):
            raise ValueError("Cache key prefix must not contain glob characters")
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix
        if backend:
            self._backend = backend
        else:
            # Try Redis first, fall back to local cache
            if REDIS_AVAILABLE:
                try:
                    self._backend = RedisCacheBackend(key_prefix=key_prefix)
                    logger.info("Using Redis cache backend")
                except Exception as e:
                    logger.warning(f"Redis initialization failed: {e}, using local cache")
                    self._backend = LocalCacheBackend()
            else:
                self._backend = LocalCacheBackend()
                logger.info("Using local cache backend")

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key."""
        return f"{self.key_prefix}:{key}"

    def get(self, key: str) -> Any | None:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        full_key = self._make_key(key)
        value = self._backend.get(full_key)
        if value is not None:
            logger.debug(f"Cache hit: {key}")
        else:
            logger.debug(f"Cache miss: {key}")
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl: Time to live in seconds (uses default_ttl if None)
        """
        full_key = self._make_key(key)
        ttl = ttl if ttl is not None else self.default_ttl
        self._backend.set(full_key, value, ttl)
        logger.debug(f"Cached: {key} (TTL: {ttl}s)")

    def delete(self, key: str) -> None:
        """Delete value from cache.

        Args:
            key: Cache key
        """
        full_key = self._make_key(key)
        self._backend.delete(full_key)
        logger.debug(f"Deleted from cache: {key}")

    def clear(self) -> None:
        """Clear all cached values."""
        self._backend.clear()

    def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if key exists and not expired
        """
        full_key = self._make_key(key)
        return self._backend.exists(full_key)

    def cached(
        self, key_prefix: str = "", ttl: int | None = None, key_builder: Callable | None = None
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator for caching function results.

        Args:
            key_prefix: Prefix for cache key (defaults to function name)
            ttl: Time to live in seconds (uses default_ttl if None)
            key_builder: Custom function to build cache key from args/kwargs

        Returns:
            Decorated function

        Example:
            ```python
            @cache.cached(ttl=600)
            def expensive_computation(x: int, y: int) -> int:
                time.sleep(5)
                return x + y

            # First call: takes 5 seconds
            result = expensive_computation(1, 2)

            # Second call: instant (cached)
            result = expensive_computation(1, 2)
            ```
        """

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            prefix = key_prefix or func.__name__

            @wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                # Build cache key
                if key_builder:
                    cache_key = f"{prefix}:{key_builder(*args, **kwargs)}"
                else:
                    cache_key = self._build_cache_key(prefix, args, kwargs)

                # Try to get from cache
                cached_value = self.get(cache_key)
                if cached_value is not None:
                    return cached_value

                # Compute and cache
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator

    def _build_cache_key(self, prefix: str, args: tuple, kwargs: dict) -> str:
        """Build cache key from function arguments."""
        # Create deterministic key from args and kwargs
        key_parts = [prefix]

        # Add positional args
        if args:
            args_str = json.dumps(args, sort_keys=True, default=str)
            key_parts.append(hashlib.sha256(args_str.encode()).hexdigest())

        # Add keyword args
        if kwargs:
            kwargs_str = json.dumps(kwargs, sort_keys=True, default=str)
            key_parts.append(hashlib.sha256(kwargs_str.encode()).hexdigest())

        return ":".join(key_parts)


# Global cache instance
_global_cache: CacheManager | None = None


def get_cache() -> CacheManager:
    """Get the global cache instance.

    Returns:
        The global cache manager

    Example:
        ```python
        from core.caching import get_cache

        cache = get_cache()
        cache.set("my_key", "my_value", ttl=300)
        value = cache.get("my_key")
        ```
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = CacheManager()
        logger.info("Global cache manager created")
    return _global_cache


def reset_cache() -> None:
    """Reset the global cache.

    Useful for testing.
    """
    global _global_cache
    if _global_cache:
        _global_cache.clear()
    _global_cache = None
    logger.debug("Global cache reset")


__all__ = [
    "CacheManager",
    "CacheBackend",
    "LocalCacheBackend",
    "RedisCacheBackend",
    "get_cache",
    "reset_cache",
    "dumps_signed",
    "loads_signed",
]
