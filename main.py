"""HOOK Cloud - Autonomous AI-Driven Deception & Sandbox Cloud (application factory).

Run (dev):   python main.py
Run (prod):  gunicorn main:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:$PORT --forwarded-allow-ips="*"
Schema:      alembic upgrade head          (the app never creates or alters tables itself)

Several workers / replicas are supported: attacker state lives in Redis (REDIS_URL). Without Redis the service
falls back to process-local memory - then run exactly ONE worker.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.config import settings
from core.redis_client import mode as redis_mode
from engine.events import flush_events
from routers import auth, projects, trap, views

log = logging.getLogger("hook")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("HOOK Cloud started: env=%s state_backend=%s db=%s", settings.ENV, redis_mode(),
             "sqlite" if settings.IS_SQLITE else "postgres")
    if redis_mode() == "memory" and settings.is_production:
        log.warning("Running WITHOUT Redis: attacker state is per-process. Use exactly one worker or set REDIS_URL.")
    yield
    flush_events()


def create_app() -> FastAPI:
    app = FastAPI(
        title="HOOK — Autonomous AI Deception & Sandbox Cloud", version="5.0", lifespan=lifespan,
        docs_url="/docs" if settings.DOCS_ENABLED else None, redoc_url=None,
        openapi_url="/openapi.json" if settings.DOCS_ENABLED else None,
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > settings.MAX_BODY_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return resp

    app.include_router(views.router)
    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(trap.router)
    return app


app = create_app()


if __name__ == "__main__":
    import os

    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "0.0.0.0" if os.getenv("PORT") else "127.0.0.1"),
                port=int(os.getenv("PORT", "8080")), proxy_headers=True,
                forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "*"))
