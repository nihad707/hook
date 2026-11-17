"""initial schema (identical to the v4.0 monolith, so existing databases can simply be stamped)

Revision ID: 0001
Revises:
Create Date: 2026-11-17
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
    )
    op.create_index(op.f("ix_users_id"), "users", ["id"])
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index(op.f("ix_projects_id"), "projects", ["id"])

    op.create_table(
        "project_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("prefix", sa.String(10), nullable=False),
        sa.Column("status", sa.String(20)),
    )
    op.create_index(op.f("ix_project_keys_id"), "project_keys", ["id"])
    op.create_index("ix_project_keys_hash", "project_keys", ["key_hash"])

    op.create_table(
        "sandbox_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("attacker_ip", sa.String(50)),
        sa.Column("agent_signature", sa.String(255)),
        sa.Column("current_stage", sa.Integer()),
        sa.Column("ai_thought_log", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("attack_type", sa.String(30)),
        sa.Column("tarpit_level", sa.Integer()),
        sa.Column("last_seen", sa.DateTime()),
    )
    op.create_index(op.f("ix_sandbox_sessions_id"), "sandbox_sessions", ["id"])
    op.create_index("ix_sandbox_project_ip", "sandbox_sessions", ["project_id", "attacker_ip"])   # replaced in 0002


def downgrade() -> None:
    op.drop_table("sandbox_sessions")
    op.drop_table("project_keys")
    op.drop_table("projects")
    op.drop_table("users")
