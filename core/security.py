"""Password hashing and signed Control Center tokens (framework-free)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time

from .config import settings


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> tuple[bool, bool]:
    """returns (valid, needs_rehash). Old accounts used bare SHA-256 and are upgraded on login."""
    if stored.startswith("scrypt$"):
        try:
            _, salt, dk = stored.split("$")
            calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
            return hmac.compare_digest(calc.hex(), dk), False
        except Exception:
            return False, False
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    ok = hmac.compare_digest(legacy, stored)
    return ok, ok


DUMMY_HASH = hash_password("dummy-password-for-timing")


def make_token(uid: int) -> str:
    body = f"{uid}.{int(time.time()) + settings.TOKEN_TTL}"
    sig = hmac.new(settings.SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}.{sig}".encode()).decode()


def parse_token(token: str) -> int | None:
    try:
        uid, exp, sig = base64.urlsafe_b64decode(token.encode()).decode().split(".")
        good = hmac.new(settings.SECRET_KEY.encode(), f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(good, sig) and int(exp) > time.time():
            return int(uid)
    except Exception:
        pass
    return None
