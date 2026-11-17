"""Landing page, Control Center shell, static assets and health probes."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import text

from core.config import BASE_DIR
from core.database import engine as db_engine
from core.redis_client import mode as redis_mode

router = APIRouter()
_STATIC, _TEMPLATES = BASE_DIR / "static", BASE_DIR / "templates"
_CACHE = {"Cache-Control": "public, max-age=86400"}


def _read(name: str) -> str:
    return (_TEMPLATES / name).read_text(encoding="utf-8")


LANDING_HTML = _read("landing.html")     # loaded once at start-up
ADMIN_HTML = _read("admin.html")


@router.get("/", response_class=HTMLResponse)
def landing_page():
    return LANDING_HTML


@router.get("/admin", response_class=HTMLResponse)
def admin_console():
    return ADMIN_HTML


@router.get("/static/logo.png", include_in_schema=False)
def static_logo():
    return FileResponse(_STATIC / "logo.png", media_type="image/png", headers=_CACHE)


@router.get("/static/favicon.png", include_in_schema=False)
@router.get("/favicon.ico", include_in_schema=False)
def static_favicon():
    return FileResponse(_STATIC / "favicon.png", media_type="image/png", headers=_CACHE)


@router.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness: the process is up."""
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
def readyz():
    """Readiness: the database answers. Redis is optional (memory fallback) and only reported."""
    try:
        with db_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "db_unavailable"})
    return {"status": "ok", "state_backend": redis_mode()}
