"""SQLAlchemy models. Schema changes go through Alembic: `alembic revision --autogenerate -m "..."`."""
from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from core.database import Base
from core.utils import utcnow


class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)


class ProjectDB(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=utcnow)
    keys = relationship("ProjectKeyDB", back_populates="project", cascade="all, delete-orphan")
    sandbox_sessions = relationship("SandboxSessionDB", back_populates="project", cascade="all, delete-orphan")


class ProjectKeyDB(Base):
    __tablename__ = "project_keys"
    __table_args__ = (Index("ix_project_keys_hash", "key_hash"),)
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    key_hash = Column(String(255), nullable=False)
    prefix = Column(String(10), nullable=False)
    status = Column(String(20), default="active")
    project = relationship("ProjectDB", back_populates="keys")


class SandboxSessionDB(Base):
    __tablename__ = "sandbox_sessions"
    # one row per (project, attacker IP): several workers may race to create it, the unique index arbitrates
    __table_args__ = (Index("uq_sandbox_project_ip", "project_id", "attacker_ip", unique=True),)
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    attacker_ip = Column(String(50))
    agent_signature = Column(String(255))
    current_stage = Column(Integer, default=1)
    ai_thought_log = Column(Text, default="AI trapped in isolated server sandbox.")
    created_at = Column(DateTime, default=utcnow)
    attack_type = Column(String(30))          # ai_agent | scanner | bruteforce | scraper | probe
    tarpit_level = Column(Integer, default=0)  # highest flood level reached
    last_seen = Column(DateTime)
    project = relationship("ProjectDB", back_populates="sandbox_sessions")
