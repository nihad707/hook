"""Projects, API keys and the attacker profiler feed."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from core.keys import invalidate, new_api_key
from models import ProjectCreate, ProjectDB, ProjectKeyDB, SandboxSessionDB
from .deps import current_user_id

router = APIRouter(tags=["projects"])


def _owned_project(db: Session, project_id: int, uid: int) -> ProjectDB:
    proj = db.query(ProjectDB).filter(ProjectDB.id == project_id, ProjectDB.user_id == uid).first()
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj


@router.get("/v1/users/{user_id}/projects")
def get_projects(user_id: int, uid: int = Depends(current_user_id), db: Session = Depends(get_db)):
    if user_id != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    projects = db.query(ProjectDB).filter(ProjectDB.user_id == user_id).order_by(ProjectDB.id).all()
    prefixes: dict[int, str] = {}
    if projects:
        rows = (db.query(ProjectKeyDB.project_id, ProjectKeyDB.prefix)
                .filter(ProjectKeyDB.project_id.in_([p.id for p in projects]), ProjectKeyDB.status == "active")
                .order_by(ProjectKeyDB.id).all())
        for pid, prefix in rows:
            prefixes.setdefault(pid, prefix)
    return [{"id": p.id, "name": p.name, "prefix": prefixes.get(p.id, "none")} for p in projects]


@router.post("/v1/projects")
def create_project(user_id: int, data: ProjectCreate, uid: int = Depends(current_user_id), db: Session = Depends(get_db)):
    if user_id != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Project name is required")
    if db.query(ProjectDB).filter(ProjectDB.user_id == uid).count() >= settings.MAX_PROJECTS_PER_USER:
        raise HTTPException(status_code=400, detail=f"Project limit reached ({settings.MAX_PROJECTS_PER_USER})")
    proj = ProjectDB(name=name, user_id=uid)
    db.add(proj)
    db.flush()
    raw_key, key_hash = new_api_key()
    db.add(ProjectKeyDB(project_id=proj.id, key_hash=key_hash, prefix=raw_key[:8]))
    db.commit()
    return {"project_id": proj.id, "api_key": raw_key}   # the only time the full key is ever visible


@router.post("/v1/projects/{project_id}/rotate-key")
def rotate_key(project_id: int, uid: int = Depends(current_user_id), db: Session = Depends(get_db)):
    """Revokes every active key of the project and issues a new one. Takes effect on all replicas at once."""
    proj = _owned_project(db, project_id, uid)
    old = db.query(ProjectKeyDB).filter(ProjectKeyDB.project_id == proj.id, ProjectKeyDB.status == "active").all()
    old_hashes = [k.key_hash for k in old]
    for k in old:
        k.status = "revoked"
    raw_key, key_hash = new_api_key()
    db.add(ProjectKeyDB(project_id=proj.id, key_hash=key_hash, prefix=raw_key[:8]))
    db.commit()
    for h in old_hashes:
        invalidate(h)
    return {"project_id": proj.id, "api_key": raw_key}


@router.delete("/v1/projects/{project_id}", status_code=204)
def delete_project(project_id: int, uid: int = Depends(current_user_id), db: Session = Depends(get_db)):
    proj = _owned_project(db, project_id, uid)
    hashes = [k.key_hash for k in proj.keys]
    db.delete(proj)                      # keys and sandbox sessions are removed by the cascade
    db.commit()
    for h in hashes:
        invalidate(h)


@router.get("/v1/projects/{project_id}/sandbox-sessions")
def get_sandbox_sessions(project_id: int, limit: int = 200, uid: int = Depends(current_user_id), db: Session = Depends(get_db)):
    _owned_project(db, project_id, uid)
    limit = max(1, min(limit, 500))
    sessions = (db.query(SandboxSessionDB).filter(SandboxSessionDB.project_id == project_id)
                .order_by(SandboxSessionDB.created_at.desc()).limit(limit).all())
    return [{
        "id": s.id,
        "ip": s.attacker_ip,
        "agent": s.agent_signature,
        "stage": s.current_stage,
        "log": s.ai_thought_log,
        "time": (s.last_seen or s.created_at).strftime("%H:%M:%S"),
        "type": s.attack_type or "unknown",
        "tarpit": s.tarpit_level or 0,
    } for s in sessions]
