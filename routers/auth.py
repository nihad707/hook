"""Control Center authentication. 429 is allowed HERE (it protects our own login), never on the trap."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from core.ratelimit import login_failures, register_attempts
from core.security import DUMMY_HASH, hash_password, make_token, verify_password
from models import EMAIL_RE, LoginPayload, RegisterPayload, UserDB

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterPayload, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    if register_attempts.blocked(ip):
        raise HTTPException(status_code=429, detail="Too many registrations from this address. Try again later.")
    register_attempts.hit(ip)
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    if db.query(UserDB).filter(UserDB.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    db.add(UserDB(email=email, password_hash=hash_password(data.password)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"status": "ok"}


@router.post("/login")
def login(data: LoginPayload, request: Request, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    throttle_key = f"{_client_ip(request)}|{email}"
    if login_failures.blocked(throttle_key):
        raise HTTPException(status_code=429,
                            detail=f"Too many failed attempts. Try again in {settings.LOGIN_LOCK_SECONDS // 60} minutes.")
    user = db.query(UserDB).filter(UserDB.email == email).first()
    if user is None:
        verify_password(data.password, DUMMY_HASH)  # equalise timing: unknown e-mail costs the same as a wrong password
        ok = False
    else:
        ok, rehash = verify_password(data.password, user.password_hash)
        if ok and rehash:
            user.password_hash = hash_password(data.password)
            db.commit()
    if not ok:
        login_failures.hit(throttle_key)
        raise HTTPException(status_code=400, detail="Invalid credentials")
    login_failures.reset(throttle_key)
    return {"user_id": user.id, "email": user.email, "token": make_token(user.id), "expires_in": settings.TOKEN_TTL}
