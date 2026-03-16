"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import hashlib
import hmac
import json
import logging
import os
# Redis values are signed with HMAC before deserialization.
import pickle  # nosec B403
import secrets
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
    """Redis cache backend with connection pooling."""

    _SIGNING_VERSION_PREFIX = b"v1:"
    _SIGNATURE_SIZE = 32  # sha256 digest length in bytes

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        max_connections: int = 10,
        signing_key: str | bytes | None = None,
    ) -> None:
        """Initialize Redis cache.

        Args:
            host: Redis server host
            port: Redis server port
            db: Redis database number
            password: Redis password (if required)
            max_connections: Maximum connections in pool
            signing_key: HMAC key used to sign serialized cache payloads
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis package not installed")

        self._signing_key = self._resolve_signing_key(signing_key)

        self._pool = ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=False,  # Use binary mode for pickle
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # Test connection
        try:
            self._client.ping()
            logger.info(f"Redis cache connected to {host}:{port}/{db}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    @staticmethod
    def _resolve_signing_key(signing_key: str | bytes | None) -> bytes:
        """Resolve signing key for cache payload HMAC verification."""
        if isinstance(signing_key, bytes) and signing_key:
            return signing_key
        if isinstance(signing_key, str) and signing_key:
            return signing_key.encode("utf-8")

        env_key = os.getenv("AUDORA_CACHE_SIGNING_KEY", "").strip()
        if env_key:
            return env_key.encode("utf-8")

        # Fallback keeps runtime safe from tampered cache values, but keys will
        # rotate per process and old cache entries become misses.
        logger.warning(
            "AUDORA_CACHE_SIGNING_KEY is not set; using an ephemeral in-memory cache signing key."
        )
        return secrets.token_bytes(32)

    def _sign_payload(self, payload: bytes) -> bytes:
        """Attach versioned HMAC signature to serialized cache payload."""
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
        return self._SIGNING_VERSION_PREFIX + signature + payload

    def _verify_signed_payload(self, signed_payload: bytes) -> bytes | None:
        """Verify signature and return payload if valid."""
        if not signed_payload.startswith(self._SIGNING_VERSION_PREFIX):
            logger.warning("Cache payload missing signature prefix; treating as cache miss")
            return None

        sig_start = len(self._SIGNING_VERSION_PREFIX)
        sig_end = sig_start + self._SIGNATURE_SIZE
        if len(signed_payload) <= sig_end:
            logger.warning("Malformed signed cache payload; treating as cache miss")
            return None

        signature = signed_payload[sig_start:sig_end]
        payload = signed_payload[sig_end:]
        expected = hmac.new(self._signing_key, payload, hashlib.sha256).digest()

        if not hmac.compare_digest(signature, expected):
            logger.warning("Cache payload signature mismatch; treating as cache miss")
            return None

        return payload

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            signed_value = self._client.get(key)
            if signed_value is None:
                return None

            payload = self._verify_signed_payload(signed_value)
            if payload is None:
                return None

            return pickle.loads(payload)  # nosec B301
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache with optional TTL."""
        try:
            serialized = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            signed_payload = self._sign_payload(serialized)
            if ttl:
                self._client.setex(key, ttl, signed_payload)
            else:
                self._client.set(key, signed_payload)
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
            key_parts.append(hashlib.sha256(args_str.encode("utf-8")).hexdigest())

        # Add keyword args
        if kwargs:
            kwargs_str = json.dumps(kwargs, sort_keys=True, default=str)
            key_parts.append(hashlib.sha256(kwargs_str.encode("utf-8")).hexdigest())

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
