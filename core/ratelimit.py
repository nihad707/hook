"""Fixed-window counters shared between workers through Redis (in-memory fallback).

Used ONLY for Control Center endpoints (login brute-force lock-out, registration spam).
The attacker-facing trap endpoint never uses it - the trap must never answer 429.
"""
from __future__ import annotations

import hashlib
import threading
import time

from .config import settings
from .redis_client import REDIS_ERRORS, get_redis, key, mark_down


class FixedWindowCounter:
    def __init__(self, name: str, limit: int, window_s: int):
        self.name, self.limit, self.window = name, limit, window_s
        self._mem: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _rkey(self, raw: str) -> str:
        return key("rl", self.name, hashlib.sha256(raw.encode()).hexdigest()[:32])

    def blocked(self, raw: str) -> bool:
        r = get_redis()
        if r is not None:
            try:
                return int(r.get(self._rkey(raw)) or 0) >= self.limit
            except REDIS_ERRORS as exc:
                mark_down(exc)
        now = time.time()
        with self._lock:
            hits = [t for t in self._mem.get(raw, []) if now - t < self.window]
            self._mem[raw] = hits
            if len(self._mem) > 5000:
                self._mem.clear()
            return len(hits) >= self.limit

    def hit(self, raw: str) -> None:
        r = get_redis()
        if r is not None:
            try:
                k = self._rkey(raw)
                pipe = r.pipeline()          # MULTI/EXEC: the window starts at the first hit
                pipe.set(k, 0, ex=self.window, nx=True)
                pipe.incr(k)
                pipe.execute()
                return
            except REDIS_ERRORS as exc:
                mark_down(exc)
        with self._lock:
            self._mem.setdefault(raw, []).append(time.time())

    def reset(self, raw: str) -> None:
        r = get_redis()
        if r is not None:
            try:
                r.delete(self._rkey(raw))
            except REDIS_ERRORS as exc:
                mark_down(exc)
        with self._lock:
            self._mem.pop(raw, None)


login_failures = FixedWindowCounter("login", settings.LOGIN_MAX_FAILS, settings.LOGIN_LOCK_SECONDS)
register_attempts = FixedWindowCounter("register", 20, 3600)
