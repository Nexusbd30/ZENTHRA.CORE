"""add tenant policy persistence

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-08-11 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    if not _has_column("policy_rules", "tenant_id"):
        op.add_column(
            "policy_rules",
            sa.Column("tenant_id", sa.String(length=120), nullable=False, server_default="default"),
        )
        op.create_index(op.f("ix_policy_rules_tenant_id"), "policy_rules", ["tenant_id"])
    if not _has_column("policy_rules", "name"):
        op.add_column(
            "policy_rules",
            sa.Column("name", sa.String(length=120), nullable=False, server_default=""),
        )
    if not _has_column("policy_rules", "provider_assignments"):
        op.add_column(
            "policy_rules",
            sa.Column("provider_assignments", sa.Text(), nullable=False, server_default="{}"),
        )
    if not _has_column("policy_rules", "enabled"):
        op.add_column(
            "policy_rules",
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        )


def downgrade() -> None:
    for column_name in ["enabled", "provider_assignments", "name"]:
        if _has_column("policy_rules", column_name):
            op.drop_column("policy_rules", column_name)
    if _has_column("policy_rules", "tenant_id"):
        op.drop_index(op.f("ix_policy_rules_tenant_id"), table_name="policy_rules")
        op.drop_column("policy_rules", "tenant_id")
