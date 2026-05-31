"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import hashlib
import json
import logging
import time
from collections.abc import Callable
from functools import wraps
from io import StringIO
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
_INVALID_CACHE_ENTRY = object()


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
    ) -> None:
        """Initialize Redis cache.

        Args:
            host: Redis server host
            port: Redis server port
            db: Redis database number
            password: Redis password (if required)
            max_connections: Maximum connections in pool
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis package not installed")

        self._pool = ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=False,  # Keep binary mode for JSON envelopes
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # Test connection
        try:
            self._client.ping()
            logger.info(f"Redis cache connected to {host}:{port}/{db}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _serialize(self, value: Any) -> bytes:
        """Serialize cache value using safe, explicit JSON envelopes."""
        payload_type, payload = self._to_safe_payload(value)
        envelope = {"v": 1, "type": payload_type, "value": payload}
        return json.dumps(envelope, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def _deserialize(self, value: bytes) -> Any | object:
        """Deserialize cache value without executing cached bytes."""
        try:
            envelope = json.loads(value.decode("utf-8"))
            if (
                not isinstance(envelope, dict)
                or envelope.get("v") != 1
                or "type" not in envelope
                or "value" not in envelope
            ):
                logger.warning("Rejected cache entry with invalid serialization envelope")
                return _INVALID_CACHE_ENTRY

            payload_type = envelope["type"]
            payload = envelope["value"]
            if payload_type == "json":
                return self._from_json_safe_value(payload)
            if payload_type == "pandas_dataframe":
                if not isinstance(payload, str):
                    logger.warning("Rejected cache DataFrame payload with invalid type")
                    return _INVALID_CACHE_ENTRY
                return pd.read_json(StringIO(payload), orient="table")

            logger.warning("Rejected cache entry with unsupported type: %s", payload_type)
            return _INVALID_CACHE_ENTRY
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning("Failed to decode cache entry safely: %s", e)
            return _INVALID_CACHE_ENTRY

    def _to_safe_payload(self, value: Any) -> tuple[str, Any]:
        """Convert supported cache values into JSON-serializable payloads."""
        if isinstance(value, pd.DataFrame):
            return "pandas_dataframe", value.to_json(orient="table", date_format="iso")
        return "json", self._to_json_safe_value(value)

    def _to_json_safe_value(self, value: Any) -> Any:
        """Return a JSON-safe value while preserving supported Python types."""
        if value is None or isinstance(value, (bool, int, float, str)):
            return {"__audora_type__": "scalar", "data": value}
        if isinstance(value, bytes):
            import base64

            return {"__audora_type__": "bytes", "data": base64.b64encode(value).decode("ascii")}
        if isinstance(value, list):
            return {
                "__audora_type__": "list",
                "items": [self._to_json_safe_value(item) for item in value],
            }
        if isinstance(value, dict):
            safe_dict = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("Redis cache only supports dictionaries with string keys")
                safe_dict[key] = self._to_json_safe_value(item)
            return {"__audora_type__": "dict", "items": safe_dict}
        raise TypeError(f"Unsupported Redis cache value type: {type(value).__name__}")

    def _from_json_safe_value(self, value: Any) -> Any:
        """Restore values encoded by _to_json_safe_value."""
        if not isinstance(value, dict) or "__audora_type__" not in value:
            raise TypeError("Invalid JSON cache payload")

        payload_type = value["__audora_type__"]
        if payload_type == "scalar":
            scalar = value.get("data")
            if scalar is None or isinstance(scalar, (bool, int, float, str)):
                return scalar
            raise TypeError("Invalid scalar cache payload")
        if payload_type == "bytes":
            import base64

            data = value.get("data")
            if not isinstance(data, str):
                raise TypeError("Invalid bytes cache payload")
            return base64.b64decode(data.encode("ascii"), validate=True)
        if payload_type == "list":
            items = value.get("items")
            if not isinstance(items, list):
                raise TypeError("Invalid list cache payload")
            return [self._from_json_safe_value(item) for item in items]
        if payload_type == "dict":
            items = value.get("items")
            if not isinstance(items, dict):
                raise TypeError("Invalid dict cache payload")
            return {key: self._from_json_safe_value(item) for key, item in items.items()}
        raise TypeError("Invalid JSON cache payload")

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            value = self._client.get(key)
            if value is None:
                return None
            deserialized = self._deserialize(value)
            if deserialized is _INVALID_CACHE_ENTRY:
                self.delete(key)
                return None
            return deserialized
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
        except (TypeError, ValueError) as e:
            logger.warning("Redis set rejected unsupported value for key %s: %s", key, e)
        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")

    def delete(self, key: str) -> None:
        """Delete value from cache."""
        try:
            self._client.delete(key)
        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {e}")

    def clear(self) -> None:
        """Clear all cached values."""
        try:
            self._client.flushdb()
            logger.debug("Cleared Redis cache")
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
        if backend:
            self._backend = backend
        else:
            # Try Redis first, fall back to local cache
            if REDIS_AVAILABLE:
                try:
                    self._backend = RedisCacheBackend()
                    logger.info("Using Redis cache backend")
                except Exception as e:
                    logger.warning(f"Redis initialization failed: {e}, using local cache")
                    self._backend = LocalCacheBackend()
            else:
                self._backend = LocalCacheBackend()
                logger.info("Using local cache backend")

        self.default_ttl = default_ttl
        self.key_prefix = key_prefix

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
            value: Value to cache (must be picklable)
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
]
