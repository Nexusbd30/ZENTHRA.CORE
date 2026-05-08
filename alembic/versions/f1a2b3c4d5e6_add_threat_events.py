"""add threat events

Revision ID: f1a2b3c4d5e6
Revises: e9f0a1b2c3d4
Create Date: 2026-05-08 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "f1a2b3c4d5e6"
down_revision = "e9f0a1b2c3d4"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return name in inspector.get_table_names()


def upgrade() -> None:
    if _has_table("threat_events"):
        return

    op.create_table(
        "threat_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("raw_payload", sa.Text(), nullable=False),
        sa.Column("normalized", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_threat_events_timestamp"), "threat_events", ["timestamp"])
    op.create_index(op.f("ix_threat_events_source"), "threat_events", ["source"])
    op.create_index(op.f("ix_threat_events_event_type"), "threat_events", ["event_type"])


def downgrade() -> None:
    if not _has_table("threat_events"):
        return

    op.drop_index(op.f("ix_threat_events_event_type"), table_name="threat_events")
    op.drop_index(op.f("ix_threat_events_source"), table_name="threat_events")
    op.drop_index(op.f("ix_threat_events_timestamp"), table_name="threat_events")
    op.drop_table("threat_events")
