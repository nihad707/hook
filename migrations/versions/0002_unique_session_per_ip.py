"""one sandbox session per (project, attacker IP): needed once several workers write concurrently

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-17
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # collapse accidental duplicates (possible with the old single-process writer after restarts), keep the oldest row
    op.execute("DELETE FROM sandbox_sessions WHERE id NOT IN "
               "(SELECT MIN(id) FROM sandbox_sessions GROUP BY project_id, attacker_ip)")
    op.execute("DROP INDEX IF EXISTS ix_sandbox_project_ip")
    op.create_index("uq_sandbox_project_ip", "sandbox_sessions", ["project_id", "attacker_ip"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_sandbox_project_ip", table_name="sandbox_sessions")
    op.create_index("ix_sandbox_project_ip", "sandbox_sessions", ["project_id", "attacker_ip"])
