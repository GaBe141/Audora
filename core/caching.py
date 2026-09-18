"""Caching system for Audora with Redis and local fallback.

Provides a unified caching interface with Redis support and automatic
fallback to in-memory caching when Redis is unavailable.
"""

import base64
import binascii
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

_CACHE_ENVELOPE_VERSION = 2
_JSON_PAYLOAD = "json"
_BYTES_PAYLOAD = "bytes"
_DATAFRAME_PAYLOAD = "pandas_dataframe"
_SIGNED_PAYLOAD_TYPES = {_JSON_PAYLOAD, _BYTES_PAYLOAD, _DATAFRAME_PAYLOAD}


def _encode_cache_payload(value: Any) -> tuple[str, str]:
    """Encode a cache value as a typed JSON-safe payload."""
    if isinstance(value, (bytes, bytearray)):
        return _BYTES_PAYLOAD, base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, pd.DataFrame):
        return _DATAFRAME_PAYLOAD, value.to_json(orient="split", date_format="iso")
    try:
        return _JSON_PAYLOAD, json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise TypeError(
            "Cache values must be JSON-serializable, bytes, or pandas DataFrames; "
            f"got {type(value).__name__}"
        ) from exc


def _decode_cache_payload(payload_type: str, payload: str) -> Any:
    """Decode a typed JSON-safe cache payload."""
    if payload_type == _BYTES_PAYLOAD:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    if payload_type == _DATAFRAME_PAYLOAD:
        return pd.read_json(StringIO(payload), orient="split")
    if payload_type == _JSON_PAYLOAD:
        return json.loads(payload)
    raise ValueError(f"Unsupported cache payload type: {payload_type}")


def _canonical_cache_body(payload_type: str, payload: str) -> bytes:
    """Build the canonical signed body for a cache envelope."""
    body_obj = {
        "p": payload,
        "t": payload_type,
        "v": _CACHE_ENVELOPE_VERSION,
    }
    return json.dumps(body_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def pack_cache_value(value: Any, signing_key: bytes) -> bytes:
    """Serialize a cache value into a signed JSON envelope.

    Pickle is intentionally not used: a compromised Redis instance must not be
    able to execute attacker-controlled bytecode in the application process.
    """
    payload_type, payload = _encode_cache_payload(value)
    body = _canonical_cache_body(payload_type, payload)
    envelope = {
        "v": _CACHE_ENVELOPE_VERSION,
        "alg": "HMAC-SHA256",
        "sig": hmac.new(signing_key, body, hashlib.sha256).hexdigest(),
        "t": payload_type,
        "p": payload,
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def unpack_cache_value(raw: bytes, signing_key: bytes) -> tuple[bool, Any]:
    """Deserialize a signed JSON envelope.

    Returns:
        (True, value) on success, (False, None) for malformed, unsigned,
        legacy pickle, or tampered payloads.
    """
    try:
        if not isinstance(raw, (bytes, bytearray)):
            return False, None
        envelope = json.loads(bytes(raw).decode("utf-8"))
        if (
            not isinstance(envelope, dict)
            or envelope.get("v") != _CACHE_ENVELOPE_VERSION
            or envelope.get("alg") != "HMAC-SHA256"
            or envelope.get("t") not in _SIGNED_PAYLOAD_TYPES
            or not isinstance(envelope.get("sig"), str)
            or not isinstance(envelope.get("p"), str)
        ):
            return False, None

        payload_type = envelope["t"]
        payload = envelope["p"]
        expected = hmac.new(
            signing_key, _canonical_cache_body(payload_type, payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(envelope["sig"], expected):
            return False, None
        return True, _decode_cache_payload(payload_type, payload)
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        binascii.Error,
        KeyError,
    ):
        return False, None


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
            key_prefix: Prefix used to scope SCAN-based clears
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis package not installed")

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
        if configured_key:
            return configured_key.encode("utf-8")

        logger.warning(
            "AUDORA_CACHE_SIGNING_KEY is not set; using process-local cache signing key. "
            "Set AUDORA_CACHE_SIGNING_KEY for shared Redis cache across processes."
        )
        return os.urandom(32)

    def _serialize(self, value: Any) -> bytes:
        """Serialize cache value as a signed JSON envelope."""
        return pack_cache_value(value, self._signing_key)

    def _deserialize(self, value: bytes) -> tuple[bool, Any]:
        """Deserialize cache value only after signature and type checks."""
        ok, decoded = unpack_cache_value(value, self._signing_key)
        if not ok:
            logger.warning("Rejected cache entry with invalid or unsafe serialization envelope")
        return ok, decoded

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            value = self._client.get(key)
            if value is None:
                return None
            ok, decoded = self._deserialize(value)
            if not ok:
                self._client.delete(key)
                return None
            return decoded
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
        """Clear cached values scoped to this backend's key prefix.

        Uses SCAN + DELETE instead of FLUSHDB so other Redis data is not wiped.
        """
        prefix = (self._key_prefix or "").strip()
        if not prefix:
            logger.warning("Refusing to clear Redis cache without a key prefix")
            return

        pattern = f"{prefix}:*"
        try:
            cursor: int | bytes = 0
            deleted = 0
            while True:
                cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    deleted += int(self._client.delete(*keys))
                if cursor in (0, "0", b"0"):
                    break
            logger.debug("Cleared %s Redis cache keys matching %s", deleted, pattern)
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
            value: Value to cache (JSON-serializable, bytes, or pandas DataFrame)
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
    "pack_cache_value",
    "unpack_cache_value",
]
