"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections.abc import Callable
from functools import wraps
from io import StringIO
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

try:
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    pd = None  # type: ignore[assignment]
    PANDAS_AVAILABLE = False

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
        self._max_payload_bytes = int(os.getenv("AUDORA_CACHE_MAX_PAYLOAD_BYTES", "2097152"))

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

    def _to_safe_payload(self, value: Any) -> Any:
        """Convert Python value to a strict JSON-safe representation."""
        if value is None or isinstance(value, (bool, int, float, str)):
            return value

        if PANDAS_AVAILABLE and isinstance(value, pd.DataFrame):
            return {
                "__audora_type__": "dataframe_split_json",
                "value": value.to_json(orient="split", date_format="iso"),
            }

        if isinstance(value, list):
            return [self._to_safe_payload(item) for item in value]

        if isinstance(value, tuple):
            return {
                "__audora_type__": "tuple",
                "items": [self._to_safe_payload(item) for item in value],
            }

        if isinstance(value, set):
            return {
                "__audora_type__": "set",
                "items": [self._to_safe_payload(item) for item in sorted(value, key=str)],
            }

        if isinstance(value, bytes):
            return {
                "__audora_type__": "bytes",
                "value": base64.b64encode(value).decode("ascii"),
            }

        if isinstance(value, dict):
            return {str(key): self._to_safe_payload(item) for key, item in value.items()}

        raise TypeError(f"Unsupported cache value type for Redis serialization: {type(value)!r}")

    def _from_safe_payload(self, value: Any) -> Any:
        """Convert strict JSON-safe representation back into Python values."""
        if isinstance(value, list):
            return [self._from_safe_payload(item) for item in value]

        if isinstance(value, dict):
            marker = value.get("__audora_type__")
            if marker == "tuple":
                return tuple(self._from_safe_payload(item) for item in value.get("items", []))
            if marker == "set":
                return set(self._from_safe_payload(item) for item in value.get("items", []))
            if marker == "bytes":
                raw = value.get("value", "")
                if not isinstance(raw, str):
                    raise ValueError("Invalid bytes payload in cache entry")
                return base64.b64decode(raw.encode("ascii"), validate=True)
            if marker == "dataframe_split_json":
                if not PANDAS_AVAILABLE:
                    raise ValueError("Pandas is required to deserialize cached DataFrame values")
                raw = value.get("value", "")
                if not isinstance(raw, str):
                    raise ValueError("Invalid DataFrame payload in cache entry")
                return pd.read_json(StringIO(raw), orient="split")
            return {str(key): self._from_safe_payload(item) for key, item in value.items()}

        return value

    def _serialize(self, value: Any) -> bytes:
        """Serialize cache value with integrity protection using safe JSON payloads."""
        payload = json.dumps(
            self._to_safe_payload(value),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(payload) > self._max_payload_bytes:
            raise ValueError(
                f"Serialized cache value exceeds size limit ({len(payload)} > {self._max_payload_bytes})"
            )
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
        envelope = {
            "v": 2,
            "alg": "HMAC-SHA256",
            "fmt": "audora-json",
            "sig": signature,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _deserialize(self, value: bytes) -> Any | None:
        """Deserialize cache value only after signature verification."""
        try:
            envelope = json.loads(value.decode("utf-8"))
            if not isinstance(envelope, dict):
                logger.warning("Rejected cache entry with invalid serialization envelope")
                return None

            if envelope.get("v") == 1:
                logger.warning("Rejected legacy cache entry using unsafe pickle serialization format")
                return None

            if (
                envelope.get("v") != 2
                or envelope.get("alg") != "HMAC-SHA256"
                or envelope.get("fmt") != "audora-json"
                or "sig" not in envelope
                or "payload" not in envelope
            ):
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

            safe_payload = json.loads(payload.decode("utf-8"))
            return self._from_safe_payload(safe_payload)
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
        except (TypeError, ValueError) as e:
            logger.warning(f"Skipping Redis cache set for key {key}: {e}")
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
            value: Value to cache (JSON-safe types or pandas DataFrame for Redis backend)
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
            key_parts.append(hashlib.sha256(args_str.encode()).hexdigest()[:16])

        # Add keyword args
        if kwargs:
            kwargs_str = json.dumps(kwargs, sort_keys=True, default=str)
            key_parts.append(hashlib.sha256(kwargs_str.encode()).hexdigest()[:16])

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
