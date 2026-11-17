"""Attacker session state shared between workers/replicas.

Redis layout (hash tag {pid:ip} keeps both keys in one cluster slot):
    hook:st:{<pid>:<ip>}    HASH  stage, tarpit, atype, login_attempts, login_goal      (TTL = STATE_TTL)
    hook:hits:{<pid>:<ip>}  ZSET  timestamps (Redis TIME, ms) of the last <=64 requests (flood window)

`touch()` is ONE atomic Lua call: stage++, flood-window update and tarpit level change happen together,
using Redis' own clock, so replicas with skewed clocks cannot disagree.
If Redis is missing or fails, the identical logic runs on process-local memory (see MemoryStateStore).
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from core.config import settings
from core.redis_client import REDIS_ERRORS, get_redis, key, mark_down


def make_seed(project_id: int, ip: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{settings.SECRET_KEY}|{project_id}|{ip}".encode()).digest()[:8], "big")


@dataclass
class AttackState:
    project_id: int
    ip: str
    seed: int
    stage: int = 0
    atype: str | None = None
    tarpit: int = 0
    login_attempts: int = 0
    login_goal: int = 0
    is_new: bool = False


_LUA_TOUCH = """
local st, hits = KEYS[1], KEYS[2]
local window, thr, low = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local maxlvl, ttl = tonumber(ARGV[4]), tonumber(ARGV[5])
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local existed = redis.call('EXISTS', st)
local stage = redis.call('HINCRBY', st, 'stage', 1)
redis.call('ZADD', hits, now, now .. ':' .. stage)
redis.call('ZREMRANGEBYSCORE', hits, '-inf', now - window)
redis.call('ZREMRANGEBYRANK', hits, 0, -65)
local rate = redis.call('ZCARD', hits)
local tarpit = tonumber(redis.call('HGET', st, 'tarpit') or '0')
if rate >= thr then
  tarpit = math.min(tarpit + 1, maxlvl)
elseif rate <= low then
  tarpit = math.max(tarpit - 1, 0)
end
redis.call('HSET', st, 'tarpit', tarpit)
redis.call('EXPIRE', st, ttl)
redis.call('EXPIRE', hits, 120)
local v = redis.call('HMGET', st, 'atype', 'login_attempts', 'login_goal')
return {existed, stage, tarpit, v[1] or '', v[2] or '0', v[3] or '0'}
"""


class MemoryStateStore:
    """Process-local fallback. Correct for one worker; several workers each see only their own share."""

    def __init__(self, max_states: int = 20000):
        self._states: "OrderedDict[tuple, AttackState]" = OrderedDict()
        self._hits: dict[tuple, deque] = {}
        self._lock = threading.Lock()
        self._max = max_states

    def touch(self, project_id: int, ip: str) -> AttackState:
        k = (project_id, ip)
        now = time.monotonic()
        with self._lock:
            st = self._states.get(k)
            is_new = st is None
            if st is None:
                st = AttackState(project_id, ip, make_seed(project_id, ip))
                self._states[k] = st
                self._hits[k] = deque(maxlen=64)
            self._states.move_to_end(k)
            st.stage += 1
            hits = self._hits.setdefault(k, deque(maxlen=64))
            hits.append(now)
            rate = sum(1 for t in hits if now - t <= settings.FLOOD_WINDOW)
            if rate >= settings.FLOOD_THRESHOLD:
                st.tarpit = min(st.tarpit + 1, settings.TARPIT_MAX_LEVEL)
            elif rate <= settings.FLOOD_THRESHOLD // 3:
                st.tarpit = max(st.tarpit - 1, 0)
            while len(self._states) > self._max:
                old, _ = self._states.popitem(last=False)
                self._hits.pop(old, None)
            # hand out a copy: the caller mutates atype / login counters and persists them via save()
            return AttackState(project_id, ip, st.seed, st.stage, st.atype, st.tarpit,
                               st.login_attempts, st.login_goal, is_new)

    def save(self, st: AttackState) -> None:
        with self._lock:
            cur = self._states.get((st.project_id, st.ip))
            if cur is not None:
                cur.atype, cur.login_attempts, cur.login_goal = st.atype, st.login_attempts, st.login_goal

    def hydrate(self, st: AttackState, prior_stage: int, prior_atype: str | None) -> None:
        with self._lock:
            cur = self._states.get((st.project_id, st.ip))
            if cur is not None:
                cur.stage += prior_stage
                cur.atype = cur.atype or prior_atype


class RedisStateStore:
    def __init__(self):
        self._script = None
        self._script_client = None

    @staticmethod
    def _keys(project_id: int, ip: str) -> tuple[str, str]:
        tag = "{%s:%s}" % (project_id, ip)
        return key("st", tag), key("hits", tag)

    def _get_script(self, r):
        if self._script is None or self._script_client is not r:
            self._script = r.register_script(_LUA_TOUCH)
            self._script_client = r
        return self._script

    def touch(self, r, project_id: int, ip: str) -> AttackState:
        st_key, hits_key = self._keys(project_id, ip)
        existed, stage, tarpit, atype, la, lg = self._get_script(r)(
            keys=[st_key, hits_key],
            args=[settings.FLOOD_WINDOW * 1000, settings.FLOOD_THRESHOLD, settings.FLOOD_THRESHOLD // 3,
                  settings.TARPIT_MAX_LEVEL, settings.STATE_TTL])
        return AttackState(project_id, ip, make_seed(project_id, ip), int(stage), atype or None, int(tarpit),
                           int(la), int(lg), is_new=not existed)

    def save(self, r, st: AttackState) -> None:
        st_key, _ = self._keys(st.project_id, st.ip)
        r.hset(st_key, mapping={"atype": st.atype or "", "login_attempts": st.login_attempts, "login_goal": st.login_goal})

    def hydrate(self, r, st: AttackState, prior_stage: int, prior_atype: str | None) -> None:
        st_key, _ = self._keys(st.project_id, st.ip)
        pipe = r.pipeline()
        if prior_stage:
            pipe.hincrby(st_key, "stage", prior_stage)
        if prior_atype and not st.atype:
            pipe.hsetnx(st_key, "atype", prior_atype)
        pipe.execute()


class StateStore:
    """Facade: Redis when available, memory otherwise. Never raises, never blocks the trap on a dead Redis."""

    def __init__(self):
        self._redis = RedisStateStore()
        self._memory = MemoryStateStore()

    def touch(self, project_id: int, ip: str) -> AttackState:
        r = get_redis()
        if r is not None:
            try:
                return self._redis.touch(r, project_id, ip)
            except REDIS_ERRORS as exc:
                mark_down(exc)
        return self._memory.touch(project_id, ip)

    def save(self, st: AttackState) -> None:
        r = get_redis()
        if r is not None:
            try:
                self._redis.save(r, st)
                return
            except REDIS_ERRORS as exc:
                mark_down(exc)
        self._memory.save(st)

    def hydrate(self, st: AttackState, prior_stage: int, prior_atype: str | None) -> None:
        """Cold start (or Redis flushed): resume the loop depth from the database."""
        st.stage += prior_stage
        st.atype = st.atype or prior_atype
        r = get_redis()
        if r is not None:
            try:
                self._redis.hydrate(r, st, prior_stage, prior_atype)
                return
            except REDIS_ERRORS as exc:
                mark_down(exc)
        self._memory.hydrate(st, prior_stage, prior_atype)


state_store = StateStore()
