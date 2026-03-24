"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import hashlib
import hmac
import io
import json
import logging
import os
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

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
    """Redis cache backend with connection pooling.

    Uses HMAC-signed JSON payloads to prevent deserializing tampered cache data.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        max_connections: int = 10,
        signing_key: str | None = None,
    ) -> None:
        """Initialize Redis cache.

        Args:
            host: Redis server host
            port: Redis server port
            db: Redis database number
            password: Redis password (if required)
            max_connections: Maximum connections in pool
            signing_key: HMAC key used to sign serialized payloads
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis package not installed")

        raw_signing_key = signing_key or os.getenv("AUDORA_CACHE_SIGNING_KEY")
        if not raw_signing_key:
            raise ValueError(
                "AUDORA_CACHE_SIGNING_KEY must be set when using Redis cache backend"
            )
        self._signing_key = raw_signing_key.encode("utf-8")

        self._pool = ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=False,  # Binary mode for signed payload bytes
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # Test connection
        try:
            self._client.ping()
            logger.info(f"Redis cache connected to {host}:{port}/{db}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            value = self._client.get(key)
            if value is None:
                return None
            return self._deserialize(value)
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

    @staticmethod
    def _is_pandas_dataframe(value: Any) -> bool:
        """Return True if value is a pandas DataFrame without importing pandas globally."""
        value_type = type(value)
        return (
            value_type.__name__ == "DataFrame"
            and value_type.__module__.split(".")[0] == "pandas"
        )

    def _to_payload_object(self, value: Any) -> dict[str, Any]:
        """Convert cache values into safe JSON payload objects."""
        if self._is_pandas_dataframe(value):
            return {
                "type": "pandas.DataFrame",
                "value": value.to_json(orient="split", date_format="iso"),
            }

        try:
            json.dumps(value)
        except (TypeError, ValueError) as e:
            raise TypeError(
                "Redis cache values must be JSON-serializable or pandas DataFrames"
            ) from e

        return {"type": "json", "value": value}

    def _from_payload_object(self, payload_object: dict[str, Any]) -> Any | None:
        """Restore cached values from payload objects."""
        payload_type = payload_object.get("type")

        if payload_type == "json":
            return payload_object.get("value")

        if payload_type == "pandas.DataFrame":
            raw_value = payload_object.get("value")
            if not isinstance(raw_value, str):
                logger.warning("Rejected pandas DataFrame payload with invalid format")
                return None
            try:
                import pandas as pd  # type: ignore[import-not-found]

                return pd.read_json(io.StringIO(raw_value), orient="split")
            except Exception as e:
                logger.error(f"Failed to deserialize cached DataFrame payload: {e}")
                return None

        logger.warning(f"Rejected cache entry with unsupported payload type: {payload_type}")
        return None

    def _serialize(self, value: Any) -> bytes:
        """Serialize and sign cached value."""
        payload_object = self._to_payload_object(value)
        payload_json = json.dumps(payload_object, separators=(",", ":"), sort_keys=True)
        signature = hmac.new(
            self._signing_key,
            payload_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        envelope = {
            "v": 1,
            "fmt": "json-safe",
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": payload_object,
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _deserialize(self, value: bytes) -> Any | None:
        """Verify signature and deserialize cached value."""
        try:
            envelope = json.loads(value.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse cached payload JSON: {e}")
            return None

        if (
            not isinstance(envelope, dict)
            or envelope.get("v") != 1
            or envelope.get("fmt") != "json-safe"
            or envelope.get("alg") != "HMAC-SHA256"
            or "sig" not in envelope
            or "payload" not in envelope
        ):
            logger.warning("Rejected cache entry with invalid serialization envelope")
            return None

        payload_object = envelope["payload"]
        if not isinstance(payload_object, dict):
            logger.warning("Rejected cache entry with non-object payload")
            return None

        payload_json = json.dumps(payload_object, separators=(",", ":"), sort_keys=True)
        expected_sig = hmac.new(
            self._signing_key,
            payload_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(envelope["sig"]), expected_sig):
            logger.warning("Rejected cache entry with invalid signature")
            return None

        return self._from_payload_object(payload_object)

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
            value: Value to cache (must be JSON-serializable or a pandas DataFrame)
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
            key_parts.append(self._stable_hash(args_str))

        # Add keyword args
        if kwargs:
            kwargs_str = json.dumps(kwargs, sort_keys=True, default=str)
            key_parts.append(self._stable_hash(kwargs_str))

        return ":".join(key_parts)

    @staticmethod
    def _stable_hash(raw: str) -> str:
        """Generate a stable SHA-256 cache key component."""
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
