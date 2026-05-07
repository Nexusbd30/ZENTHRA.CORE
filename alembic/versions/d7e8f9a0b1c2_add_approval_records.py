"""add approval records

Revision ID: d7e8f9a0b1c2
Revises: c1a2b3c4d5e6
Create Date: 2026-05-07 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "d7e8f9a0b1c2"
down_revision = "c1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approval_records",
        sa.Column("approval_id", sa.String(length=36), nullable=False),
        sa.Column("verdict_id", sa.String(length=36), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("approver", sa.String(length=120), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("approval_id"),
        sa.UniqueConstraint("signature"),
    )
    op.create_index(
        op.f("ix_approval_records_verdict_id"),
        "approval_records",
        ["verdict_id"],
    )
    op.create_index(
        op.f("ix_approval_records_approver"),
        "approval_records",
        ["approver"],
    )
    op.create_index(
        op.f("ix_approval_records_signature"),
        "approval_records",
        ["signature"],
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_approval_records_signature"), table_name="approval_records")
    op.drop_index(op.f("ix_approval_records_approver"), table_name="approval_records")
    op.drop_index(op.f("ix_approval_records_verdict_id"), table_name="approval_records")
    op.drop_table("approval_records")
