"""add enterprise audit context

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5
Create Date: 2026-05-26 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b1c2d3e4f5a6"
down_revision = "a0b1c2d3e4f5"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add_column(table_name: str, column: sa.Column) -> None:
    if table_name not in _tables():
        return
    if column.name in _columns(table_name):
        return
    op.add_column(table_name, column)


def _drop_column(table_name: str, column_name: str) -> None:
    if table_name not in _tables():
        return
    if column_name not in _columns(table_name):
        return
    op.drop_column(table_name, column_name)


def upgrade() -> None:
    for column in [
        sa.Column("actor_role", sa.String(length=64), nullable=False, server_default="system"),
        sa.Column("tenant_id", sa.String(length=120), nullable=False, server_default="default"),
        sa.Column("capability", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(length=120), nullable=False, server_default=""),
    ]:
        _add_column("audit_records", column)

    if "audit_records" in _tables():
        existing_indexes = {
            index["name"] for index in sa.inspect(op.get_bind()).get_indexes("audit_records")
        }
        if "ix_audit_records_actor_role" not in existing_indexes:
            op.create_index("ix_audit_records_actor_role", "audit_records", ["actor_role"])
        if "ix_audit_records_tenant_id" not in existing_indexes:
            op.create_index("ix_audit_records_tenant_id", "audit_records", ["tenant_id"])
        if "ix_audit_records_capability" not in existing_indexes:
            op.create_index("ix_audit_records_capability", "audit_records", ["capability"])


def downgrade() -> None:
    if "audit_records" in _tables():
        existing_indexes = {
            index["name"] for index in sa.inspect(op.get_bind()).get_indexes("audit_records")
        }
        for index_name in [
            "ix_audit_records_capability",
            "ix_audit_records_tenant_id",
            "ix_audit_records_actor_role",
        ]:
            if index_name in existing_indexes:
                op.drop_index(index_name, table_name="audit_records")

    for column_name in ["request_id", "capability", "tenant_id", "actor_role"]:
        _drop_column("audit_records", column_name)
