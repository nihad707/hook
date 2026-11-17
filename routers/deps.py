from __future__ import annotations

from fastapi import Header, HTTPException

from core.security import parse_token


def current_user_id(authorization: str | None = Header(default=None, max_length=512)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    uid = parse_token(authorization[7:].strip())
    if uid is None:
        raise HTTPException(status_code=401, detail="Session expired, please log in again")
    return uid
