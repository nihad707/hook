"""Write-behind log of attacker events: the trap answers from memory, the database is written afterwards.

Each process has its own queue (cheap, lock-free on the hot path). Several processes may flush the same
attacker concurrently: the unique index (project_id, attacker_ip) decides who creates the row, everybody
else updates it.
"""
from __future__ import annotations

import logging
import threading
from collections import deque

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import settings
from core.database import SessionLocal
from core.utils import trim_log, utcnow
from models import SandboxSessionDB

log = logging.getLogger("hook.events")

EVENTS: deque = deque(maxlen=settings.EVENT_QUEUE_MAX)
_FLUSH_LOCK = threading.Lock()


def _log_lines(evs: list) -> list[str]:
    return [f"[Loop Stage {e['stage']}] {e['atype']} · {e['method']} {e['path']} → {e['vector']}"
            + (f" · tarpit {e['delay']}ms" if e["tarpit"] else "") for e in evs[-25:]]


def _upsert(db: Session, pid: int, ip: str, evs: list) -> None:
    last = evs[-1]
    lines = _log_lines(evs)
    for _ in range(3):
        row = (db.query(SandboxSessionDB)
               .filter(SandboxSessionDB.project_id == pid, SandboxSessionDB.attacker_ip == ip)
               .with_for_update().first())          # FOR UPDATE is ignored on SQLite
        if row is None:
            row = SandboxSessionDB(
                project_id=pid, attacker_ip=ip, agent_signature=last["ua"][:255], current_stage=0,
                ai_thought_log=f"AI Agent captured. Spawned in virtual server sandbox ({last['persona']}).",
                created_at=utcnow())
            db.add(row)
        row.current_stage = max(row.current_stage or 0, max(e["stage"] for e in evs))
        row.attack_type = last["atype"]
        row.tarpit_level = max(row.tarpit_level or 0, max(e["tarpit"] for e in evs))
        row.last_seen = utcnow()
        row.ai_thought_log = trim_log((row.ai_thought_log or "") + "\n" + "\n".join(lines))
        try:
            db.commit()
            return
        except IntegrityError:      # another worker created the same row first -> re-read it and update
            db.rollback()
    log.warning("could not persist session %s/%s after retries", pid, ip)


def _write_batch(batch: list) -> None:
    groups: dict = {}
    for e in batch:
        groups.setdefault((e["pid"], e["ip"]), []).append(e)
    db = SessionLocal()
    try:
        for (pid, ip), evs in groups.items():
            try:
                _upsert(db, pid, ip, evs)
            except Exception:
                db.rollback()
                log.exception("failed to persist events for %s/%s", pid, ip)
    finally:
        db.close()


def flush_events() -> None:
    """Runs as a BackgroundTask. Coalesces bursts: one writer drains everything queued by the others."""
    while True:
        if not _FLUSH_LOCK.acquire(blocking=False):
            return
        try:
            while EVENTS:
                batch = []
                while EVENTS and len(batch) < 500:
                    try:
                        batch.append(EVENTS.popleft())
                    except IndexError:
                        break
                if batch:
                    _write_batch(batch)
        finally:
            _FLUSH_LOCK.release()
        if not EVENTS:
            return
