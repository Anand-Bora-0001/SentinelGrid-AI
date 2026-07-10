"""
Redis-based caching layer with graceful fallback to in-memory.
Works with Upstash (serverless Redis) or local Redis via Docker.
Falls back silently to dict-based cache when Redis is unavailable.
"""
import json
import time
import logging
import os
from typing import Optional, Any
from functools import wraps

logger = logging.getLogger(__name__)

# ========================
# CACHE BACKEND RESOLUTION
# ========================

REDIS_URL = os.getenv("REDIS_URL", "")
_redis_client = None
_using_redis = False

try:
    if REDIS_URL:
        import redis
        _redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=2,
            retry_on_timeout=True,
        )
        # Test connection
        _redis_client.ping()
        _using_redis = True
        logger.info(f"🔴 Redis cache connected: {REDIS_URL[:30]}...")
except Exception as e:
    logger.warning(f"⚠️ Redis not available ({e}), using in-memory cache")
    _redis_client = None
    _using_redis = False


# ========================
# IN-MEMORY FALLBACK CACHE
# ========================

class _InMemoryCache:
    """Simple TTL-based in-memory cache (fallback when Redis is down)"""

    def __init__(self, max_size: int = 1000):
        self._store: dict = {}
        self._ttls: dict = {}
        self._max_size = max_size

    def get(self, key: str) -> Optional[str]:
        if key in self._ttls and time.time() > self._ttls[key]:
            del self._store[key]
            del self._ttls[key]
            return None
        return self._store.get(key)

    def set(self, key: str, value: str, ex: int = 60) -> bool:
        # Evict oldest if at capacity
        if len(self._store) >= self._max_size and key not in self._store:
            oldest = next(iter(self._store))
            del self._store[oldest]
            self._ttls.pop(oldest, None)
        self._store[key] = value
        self._ttls[key] = time.time() + ex
        return True

    def delete(self, key: str) -> int:
        removed = key in self._store
        self._store.pop(key, None)
        self._ttls.pop(key, None)
        return 1 if removed else 0

    def flushall(self):
        self._store.clear()
        self._ttls.clear()

    def keys(self, pattern: str = "*") -> list:
        if pattern == "*":
            return list(self._store.keys())
        import fnmatch
        return [k for k in self._store.keys() if fnmatch.fnmatch(k, pattern)]

    def info(self) -> dict:
        return {
            "backend": "in-memory",
            "keys": len(self._store),
            "max_size": self._max_size,
        }


_fallback_cache = _InMemoryCache()

# ========================
# UNIFIED CACHE API
# ========================

def cache_get(key: str) -> Optional[str]:
    """Get value from cache (Redis or in-memory)"""
    try:
        if _using_redis and _redis_client:
            return _redis_client.get(key)
        return _fallback_cache.get(key)
    except Exception as e:
        logger.warning(f"Cache GET error: {e}")
        return _fallback_cache.get(key)


def cache_set(key: str, value: str, ttl_seconds: int = 60) -> bool:
    """Set value in cache with TTL"""
    try:
        if _using_redis and _redis_client:
            return _redis_client.set(key, value, ex=ttl_seconds)
        return _fallback_cache.set(key, value, ex=ttl_seconds)
    except Exception as e:
        logger.warning(f"Cache SET error: {e}")
        return _fallback_cache.set(key, value, ex=ttl_seconds)


def cache_delete(key: str) -> int:
    """Delete key from cache"""
    try:
        if _using_redis and _redis_client:
            return _redis_client.delete(key)
        return _fallback_cache.delete(key)
    except Exception as e:
        logger.warning(f"Cache DELETE error: {e}")
        return _fallback_cache.delete(key)


def cache_flush():
    """Clear all cache"""
    try:
        if _using_redis and _redis_client:
            _redis_client.flushall()
        else:
            _fallback_cache.flushall()
        logger.info("🧹 Cache flushed")
    except Exception as e:
        logger.warning(f"Cache FLUSH error: {e}")
        _fallback_cache.flushall()


def cache_get_json(key: str) -> Optional[Any]:
    """Get JSON-decoded value from cache"""
    raw = cache_get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def cache_set_json(key: str, value: Any, ttl_seconds: int = 60) -> bool:
    """Set JSON-encoded value in cache"""
    return cache_set(key, json.dumps(value, default=str), ttl_seconds)


def get_cache_info() -> dict:
    """Cache backend info for health checks"""
    if _using_redis and _redis_client:
        try:
            info = _redis_client.info("memory")
            return {
                "backend": "redis",
                "connected": True,
                "used_memory": info.get("used_memory_human", "unknown"),
                "url_masked": REDIS_URL[:25] + "..." if len(REDIS_URL) > 25 else REDIS_URL,
            }
        except Exception:
            return {"backend": "redis", "connected": False}
    return _fallback_cache.info()


# ========================
# DECORATOR: Cacheable
# ========================

def cached(key_prefix: str, ttl: int = 30):
    """
    Decorator to cache function results.
    Usage:
        @cached("stats", ttl=10)
        def get_statistics(user_id):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Build cache key from prefix + args
            cache_key = f"{key_prefix}:{hash(str(args) + str(kwargs))}"
            cached_result = cache_get_json(cache_key)
            if cached_result is not None:
                return cached_result
            result = func(*args, **kwargs)
            cache_set_json(cache_key, result, ttl)
            return result
        return wrapper
    return decorator
