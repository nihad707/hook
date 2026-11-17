"""Lazy Redis client with a tiny circuit breaker.

Contract for every caller:
    r = get_redis()
    if r is not None:
        try: ...
        except REDIS_ERRORS as exc: mark_down(exc)
    # fall through to the in-memory implementation

If Redis is not configured, not installed or unreachable, `get_redis()` returns None and the service keeps
working on process-local memory (correct for ONE worker, degraded for many). After a failure Redis is not
retried for RETRY_AFTER seconds, so a dead Redis never adds latency to the trap.
"""
from __future__ import annotations

import logging
import threading
import time

from .config import settings

log = logging.getLogger("hook.redis")

try:
    import redis as _redis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover
    _redis = None

    class RedisError(Exception):  # type: ignore[no-redef]
        pass

REDIS_ERRORS = (RedisError, OSError)
RETRY_AFTER = 10.0

_client = None
_down_until = 0.0
_lock = threading.Lock()


def get_redis():
    global _client
    if _redis is None or not settings.REDIS_URL:
        return None
    if time.monotonic() < _down_until:
        return None
    if _client is None:
        with _lock:
            if _client is None:
                _client = _redis.Redis.from_url(
                    settings.REDIS_URL, decode_responses=True,
                    socket_timeout=settings.REDIS_TIMEOUT, socket_connect_timeout=0.5,
                    health_check_interval=30,
                )
    return _client


def mark_down(exc: Exception) -> None:
    global _down_until
    _down_until = time.monotonic() + RETRY_AFTER
    log.warning("Redis unavailable (%s) -> in-memory fallback for %.0fs", exc, RETRY_AFTER)


def key(*parts: object) -> str:
    return ":".join([settings.REDIS_PREFIX, *map(str, parts)])


def ping() -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        return bool(r.ping())
    except REDIS_ERRORS as exc:
        mark_down(exc)
        return False


def mode() -> str:
    return "redis" if get_redis() is not None else "memory"
