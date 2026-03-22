"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import base64
import datetime as dt
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

try:
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

_SERIALIZED_TYPE_KEY = "__audora_cache_type__"


def _encode_cache_value(value: Any) -> Any:
    """Encode a Python object into a JSON-safe representation."""
    if value is None or isinstance(value, bool | int | float | str):
        return value

    if isinstance(value, bytes):
        return {
            _SERIALIZED_TYPE_KEY: "bytes",
            "value": base64.b64encode(value).decode("ascii"),
        }

    if isinstance(value, dt.datetime):
        return {_SERIALIZED_TYPE_KEY: "datetime", "value": value.isoformat()}

    if isinstance(value, dt.date):
        return {_SERIALIZED_TYPE_KEY: "date", "value": value.isoformat()}

    if isinstance(value, tuple):
        return {
            _SERIALIZED_TYPE_KEY: "tuple",
            "items": [_encode_cache_value(item) for item in value],
        }

    if isinstance(value, set):
        return {
            _SERIALIZED_TYPE_KEY: "set",
            "items": [_encode_cache_value(item) for item in sorted(value, key=repr)],
        }

    if isinstance(value, list):
        return [_encode_cache_value(item) for item in value]

    if isinstance(value, dict):
        return {
            _SERIALIZED_TYPE_KEY: "dict",
            "items": [
                [_encode_cache_value(key), _encode_cache_value(item)]
                for key, item in value.items()
            ],
        }

    if PANDAS_AVAILABLE and isinstance(value, pd.DataFrame):
        return {
            _SERIALIZED_TYPE_KEY: "dataframe",
            "orient": "split",
            "value": value.to_json(orient="split", date_format="iso"),
        }

    raise TypeError(f"Unsupported cache value type for safe serialization: {type(value)!r}")


def _decode_cache_value(value: Any) -> Any:
    """Decode a JSON-safe representation into a Python object."""
    if value is None or isinstance(value, bool | int | float | str):
        return value

    if isinstance(value, list):
        return [_decode_cache_value(item) for item in value]

    if not isinstance(value, dict):
        raise TypeError(f"Invalid serialized cache payload type: {type(value)!r}")

    value_type = value.get(_SERIALIZED_TYPE_KEY)
    if value_type is None:
        return {k: _decode_cache_value(v) for k, v in value.items()}

    if value_type == "bytes":
        raw_value = value.get("value")
        if not isinstance(raw_value, str):
            raise TypeError("Serialized bytes payload is invalid")
        return base64.b64decode(raw_value.encode("ascii"), validate=True)

    if value_type == "datetime":
        raw_value = value.get("value")
        if not isinstance(raw_value, str):
            raise TypeError("Serialized datetime payload is invalid")
        return dt.datetime.fromisoformat(raw_value)

    if value_type == "date":
        raw_value = value.get("value")
        if not isinstance(raw_value, str):
            raise TypeError("Serialized date payload is invalid")
        return dt.date.fromisoformat(raw_value)

    if value_type == "tuple":
        items = value.get("items")
        if not isinstance(items, list):
            raise TypeError("Serialized tuple payload is invalid")
        return tuple(_decode_cache_value(item) for item in items)

    if value_type == "set":
        items = value.get("items")
        if not isinstance(items, list):
            raise TypeError("Serialized set payload is invalid")
        return set(_decode_cache_value(item) for item in items)

    if value_type == "dict":
        items = value.get("items")
        if not isinstance(items, list):
            raise TypeError("Serialized dict payload is invalid")
        decoded: dict[Any, Any] = {}
        for item in items:
            if not isinstance(item, list) or len(item) != 2:
                raise TypeError("Serialized dict item is invalid")
            decoded[_decode_cache_value(item[0])] = _decode_cache_value(item[1])
        return decoded

    if value_type == "dataframe":
        if not PANDAS_AVAILABLE:
            raise RuntimeError("pandas is required to deserialize cached DataFrame values")
        raw_value = value.get("value")
        orient = value.get("orient", "split")
        if not isinstance(raw_value, str):
            raise TypeError("Serialized dataframe payload is invalid")
        return pd.read_json(io.StringIO(raw_value), orient=orient)

    raise TypeError(f"Unknown serialized cache value type: {value_type}")


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
        if configured_key:
            return configured_key.encode("utf-8")

        # Fallback to process-local random key to prevent unsigned pickle loading.
        # This keeps the cache safe by default, with only a reduced cross-process hit rate.
        logger.warning(
            "AUDORA_CACHE_SIGNING_KEY is not set; using process-local cache signing key. "
            "Set AUDORA_CACHE_SIGNING_KEY for shared Redis cache across processes."
        )
        return os.urandom(32)

    def _serialize(self, value: Any) -> bytes:
        """Serialize cache value with integrity protection."""
        payload = json.dumps(_encode_cache_value(value), separators=(",", ":")).encode("utf-8")
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
        envelope = {
            "v": 2,
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _deserialize(self, value: bytes) -> Any | None:
        """Deserialize cache value only after signature verification.

        Legacy pickle-based payloads are intentionally rejected to remove
        deserialization RCE risk from tampered cache entries.
        """
        try:
            envelope = json.loads(value.decode("utf-8"))
            if (
                not isinstance(envelope, dict)
                or envelope.get("v") != 2
                or envelope.get("alg") != "HMAC-SHA256"
                or "sig" not in envelope
                or "payload" not in envelope
            ):
                if isinstance(envelope, dict) and envelope.get("v") == 1:
                    logger.warning(
                        "Rejected legacy pickle-based cache entry format; value will be recomputed"
                    )
                else:
                    logger.warning("Rejected cache entry with invalid serialization envelope")
                return None

            payload_b64 = envelope["payload"]
            if not isinstance(payload_b64, str):
                logger.warning("Rejected cache entry with non-string payload")
                return None

            payload = base64.b64decode(payload_b64.encode("ascii"), validate=True)
            expected_sig = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(envelope["sig"]), expected_sig):
                logger.warning("Rejected cache entry with invalid signature")
                return None

            decoded_payload = json.loads(payload.decode("utf-8"))
            return _decode_cache_value(decoded_payload)
        except Exception as e:
            logger.error(f"Failed to deserialize cache entry: {e}")
            return None

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
            value: Value to cache (must be safely JSON-serializable by cache encoder)
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
