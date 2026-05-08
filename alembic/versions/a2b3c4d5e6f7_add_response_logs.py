"""add response logs

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-08 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a2b3c4d5e6f7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return name in inspector.get_table_names()


def upgrade() -> None:
    if _has_table("response_logs"):
        return

    op.create_table(
        "response_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_size", sa.Integer(), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("sample", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_response_logs_timestamp"), "response_logs", ["timestamp"])
    op.create_index(op.f("ix_response_logs_source"), "response_logs", ["source"])
    op.create_index(op.f("ix_response_logs_source_ip"), "response_logs", ["source_ip"])
    op.create_index(op.f("ix_response_logs_payload_hash"), "response_logs", ["payload_hash"])
    op.create_index(op.f("ix_response_logs_status"), "response_logs", ["status"])


def downgrade() -> None:
    if not _has_table("response_logs"):
        return

    op.drop_index(op.f("ix_response_logs_status"), table_name="response_logs")
    op.drop_index(op.f("ix_response_logs_payload_hash"), table_name="response_logs")
    op.drop_index(op.f("ix_response_logs_source_ip"), table_name="response_logs")
    op.drop_index(op.f("ix_response_logs_source"), table_name="response_logs")
    op.drop_index(op.f("ix_response_logs_timestamp"), table_name="response_logs")
    op.drop_table("response_logs")
