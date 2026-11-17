"""Project API keys: generation, hashing and a Redis-shared lookup cache.

A cache hit means the trap needs no SQL at all. Revocation (`invalidate`) removes the entry from Redis,
so it takes effect on every replica immediately.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time

from sqlalchemy.orm import Session

from .redis_client import REDIS_ERRORS, get_redis, key, mark_down

_POS_TTL, _NEG_TTL = 60, 20
_local: dict[str, tuple[int | None, float]] = {}   # only used while Redis is down / not configured
_local_lock = threading.Lock()


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_api_key() -> tuple[str, str]:
    raw = f"hook_{secrets.token_hex(20)}"
    return raw, hash_key(raw)


def _cache_get(kh: str) -> tuple[bool, int | None]:
    r = get_redis()
    if r is not None:
        try:
            v = r.get(key("key", kh))
            if v is None:
                return False, None
            return True, (None if v == "-" else int(v))
        except REDIS_ERRORS as exc:
            mark_down(exc)
    with _local_lock:
        hit = _local.get(kh)
    if hit and hit[1] > time.monotonic():
        return True, hit[0]
    return False, None


def _cache_set(kh: str, pid: int | None) -> None:
    ttl = _POS_TTL if pid is not None else _NEG_TTL
    r = get_redis()
    if r is not None:
        try:
            r.set(key("key", kh), "-" if pid is None else str(pid), ex=ttl)
            return
        except REDIS_ERRORS as exc:
            mark_down(exc)
    with _local_lock:
        if len(_local) > 5000:
            _local.clear()
        _local[kh] = (pid, time.monotonic() + ttl)


def invalidate(kh: str) -> None:
    r = get_redis()
    if r is not None:
        try:
            r.delete(key("key", kh))
        except REDIS_ERRORS as exc:
            mark_down(exc)
    with _local_lock:
        _local.pop(kh, None)


def resolve_project(db: Session, raw_key: str) -> int | None:
    from models import ProjectKeyDB  # local import: core must not depend on models at import time

    if not raw_key.startswith("hook_") or len(raw_key) > 128:
        return None
    kh = hash_key(raw_key)
    hit, pid = _cache_get(kh)
    if hit:
        return pid
    row = db.query(ProjectKeyDB.project_id).filter(ProjectKeyDB.key_hash == kh, ProjectKeyDB.status == "active").first()
    pid = row[0] if row else None
    _cache_set(kh, pid)
    return pid
