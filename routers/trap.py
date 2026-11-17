"""POST /v1/hook/trap - called by the HOOK SDK for every suspicious request of a protected app.

Design rules:
  * the answer is built in memory and returned immediately; all database writes go to BackgroundTasks;
  * NEVER 403/429 for attacker traffic: floods get slower (delay hint) and deeper (loops), not blocked;
  * attacker-controlled fields are truncated by the schema, so they can never make the trap fail;
  * a failing Redis / engine degrades to a generic fake answer, never to an error page.
  (403 is returned only for an invalid HOOK API key - that is our own SDK talking, not an attacker.)
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from core.database import get_db
from core.keys import resolve_project
from core.utils import clean
from engine import classify, compute_delay, deceive, persona_label, state_store
from engine.events import EVENTS, flush_events
from models import SandboxHookPayload, SandboxSessionDB

log = logging.getLogger("hook.trap")
router = APIRouter(tags=["trap"])


def _hydrate_from_db(st, db: Session) -> None:
    """First time this process/Redis sees the attacker: continue the loop depth recorded in the database."""
    try:
        row = db.query(SandboxSessionDB.current_stage, SandboxSessionDB.attack_type).filter(
            SandboxSessionDB.project_id == st.project_id, SandboxSessionDB.attacker_ip == st.ip).first()
        if row and (row[0] or row[1]):
            state_store.hydrate(st, row[0] or 0, row[1])
    except Exception:
        log.exception("state hydrate failed")


@router.post("/v1/hook/trap")
def hook_sandbox_engine(payload: SandboxHookPayload, background: BackgroundTasks, db: Session = Depends(get_db),
                        authorization: str = Header(..., max_length=256),
                        x_hook_sdk: str | None = Header(default=None, max_length=8)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    project_id = resolve_project(db, authorization[7:].strip())
    if project_id is None:
        raise HTTPException(status_code=403, detail="Invalid HOOK API key")

    ip = clean(payload.attacker_ip, 45) or "unknown"
    ua = clean(payload.user_agent, 512).lower()
    path = clean(payload.request_path, 1024).split("?")[0] or "/"
    query = clean(payload.payload_data, 2048)
    method = (clean(payload.method, 10) or "GET").upper()

    try:
        st = state_store.touch(project_id, ip)               # one atomic step: stage++, flood window, tarpit level
        if st.is_new:
            _hydrate_from_db(st, db)
        kind = classify(ua, path.lower(), method, st)
        if st.atype in (None, "", "probe") or kind in ("ai_agent", "scanner"):
            st.atype = kind
        delay_ms = compute_delay(st.tarpit)
        vector, http_status, ctype, body = deceive(st, path, query, method)
        state_store.save(st)                                 # atype + login-lure counters -> Redis

        EVENTS.append({"pid": project_id, "ip": ip, "ua": clean(ua, 255), "path": clean(path, 120), "method": method,
                       "stage": st.stage, "atype": st.atype, "vector": vector, "tarpit": st.tarpit,
                       "delay": delay_ms, "persona": persona_label(st.seed)})
        background.add_task(flush_events)
    except Exception:
        log.exception("trap engine failure - serving generic decoy")
        vector, http_status, ctype, delay_ms = "fallback", 200, "application/json", 120
        body = {"data": [], "page": 1, "has_more": True, "next": "?page=2"}

    if (x_hook_sdk or "").strip() == "2":   # SDK v2: raw content type + status + tarpit hint
        raw = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"))
        return Response(content=raw, media_type=ctype.split(";")[0],
                        headers={"X-Hook-Status": str(http_status), "X-Hook-Delay-Ms": str(delay_ms), "X-Hook-Vector": vector})
    # legacy SDKs (hooksec <= 1.x / hook_sdk v1) expect a JSON object with HTTP 200
    return JSONResponse(status_code=200, content=body if isinstance(body, (dict, list)) else {"content": body, "content_type": ctype})
