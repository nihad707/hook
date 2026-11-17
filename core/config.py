"""Central configuration. Every environment variable of the service is read here and nowhere else.

Environment:
  HOOK_ENV                development (default) | production  (production refuses to start without a secret)
  HOOK_SECRET_KEY         signs Control Center tokens AND derives attacker personas.
                          MUST be identical on every replica/worker (>= 16 random chars).
  DATABASE_URL            sqlite:///./hook_cloud.db (default) | postgres://... (Railway/Render/Heroku style is accepted)
  REDIS_URL               redis://... | rediss://...   empty -> in-memory fallback (single process only!)
  HOOK_TOKEN_TTL_HOURS    login token lifetime, default 12
  HOOK_FLOOD_THRESHOLD    requests per 10 s that count as a flood, default 10 (3..60)
  HOOK_TARPIT_MAX_MS      max artificial delay hint sent to the SDK, default 15000
  HOOK_STATE_TTL_HOURS    how long an idle attacker state lives in Redis, default 24
  HOOK_LOGIN_MAX_FAILS    failed Control Center logins before a lock-out, default 10
  HOOK_LOGIN_LOCK_SECONDS lock-out window, default 900
  HOOK_DB_POOL_SIZE / HOOK_DB_MAX_OVERFLOW   per-process Postgres pool, default 5 / 10
  HOOK_DOCS               set to 0 to hide /docs and /openapi.json
  LOG_LEVEL               INFO (default)
"""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
log = logging.getLogger("hook")


def _int(name: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        value = default
    if lo is not None:
        value = max(lo, value)
    if hi is not None:
        value = min(hi, value)
    return value


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", "sqlite:///./hook_cloud.db")
    if url.startswith("postgres://"):  # Railway/Heroku style -> SQLAlchemy dialect name
        url = "postgresql://" + url[len("postgres://"):]
    return url


@dataclass(frozen=True)
class Settings:
    ENV: str
    LOG_LEVEL: str
    DATABASE_URL: str
    IS_SQLITE: bool
    DB_POOL_SIZE: int
    DB_MAX_OVERFLOW: int
    REDIS_URL: str
    REDIS_PREFIX: str
    REDIS_TIMEOUT: float
    STATE_TTL: int
    SECRET_KEY: str
    TOKEN_TTL: int
    FLOOD_WINDOW: float
    FLOOD_THRESHOLD: int
    TARPIT_MAX_LEVEL: int
    TARPIT_MAX_MS: int
    MAX_BODY_BYTES: int
    MAX_PROJECTS_PER_USER: int
    LOGIN_MAX_FAILS: int
    LOGIN_LOCK_SECONDS: int
    EVENT_QUEUE_MAX: int
    DOCS_ENABLED: bool

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"


def load_settings() -> Settings:
    env = os.getenv("HOOK_ENV", "development").strip().lower()
    secret = os.getenv("HOOK_SECRET_KEY") or ""
    if len(secret) < 16:
        if env == "production":
            raise RuntimeError("HOOK_SECRET_KEY (>= 16 random chars) is required when HOOK_ENV=production. "
                               "It must be the same on every replica.")
        secret = secrets.token_hex(32)
        log.warning("HOOK_SECRET_KEY is not set: using a random key. Logins reset on every restart and "
                    "multiple workers will NOT agree with each other. Set HOOK_SECRET_KEY.")
    db_url = _database_url()
    return Settings(
        ENV=env,
        LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO").upper(),
        DATABASE_URL=db_url,
        IS_SQLITE=db_url.startswith("sqlite"),
        DB_POOL_SIZE=_int("HOOK_DB_POOL_SIZE", 5, 1, 50),
        DB_MAX_OVERFLOW=_int("HOOK_DB_MAX_OVERFLOW", 10, 0, 100),
        REDIS_URL=(os.getenv("REDIS_URL") or os.getenv("HOOK_REDIS_URL") or "").strip(),
        REDIS_PREFIX=os.getenv("HOOK_REDIS_PREFIX", "hook"),
        REDIS_TIMEOUT=0.25,                      # the trap must stay fast: a slow Redis counts as a dead Redis
        STATE_TTL=_int("HOOK_STATE_TTL_HOURS", 24, 1, 720) * 3600,
        SECRET_KEY=secret,
        TOKEN_TTL=_int("HOOK_TOKEN_TTL_HOURS", 12, 1, 24 * 30) * 3600,
        FLOOD_WINDOW=10.0,
        FLOOD_THRESHOLD=_int("HOOK_FLOOD_THRESHOLD", 10, 3, 60),
        TARPIT_MAX_LEVEL=12,
        TARPIT_MAX_MS=_int("HOOK_TARPIT_MAX_MS", 15000, 500),
        MAX_BODY_BYTES=64 * 1024,
        MAX_PROJECTS_PER_USER=25,
        LOGIN_MAX_FAILS=_int("HOOK_LOGIN_MAX_FAILS", 10, 3, 100),
        LOGIN_LOCK_SECONDS=_int("HOOK_LOGIN_LOCK_SECONDS", 900, 30),
        EVENT_QUEUE_MAX=20000,
        DOCS_ENABLED=os.getenv("HOOK_DOCS", "1") != "0",
    )


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
settings = load_settings()
