"""add audit records

Revision ID: c1a2b3c4d5e6
Revises: b58a70ea4839
Create Date: 2026-05-07 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "c1a2b3c4d5e6"
down_revision = "b58a70ea4839"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_records",
        sa.Column("record_id", sa.String(length=36), nullable=False),
        sa.Column("verdict_id", sa.String(length=36), nullable=False),
        sa.Column("hash_prev", sa.String(length=128), nullable=False),
        sa.Column("hash_self", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("record_id"),
    )
    op.create_index(op.f("ix_audit_records_verdict_id"), "audit_records", ["verdict_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_records_verdict_id"), table_name="audit_records")
    op.drop_table("audit_records")
