"""init schema

Revision ID: b58a70ea4839
Revises:
Create Date: 2025-12-28 16:41:02.218515

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "b58a70ea4839"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ==========================================================
    # USERS
    # ==========================================================
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)

    # ==========================================================
    # THREATS
    #
    # ✅ SQLite compatibility:
    # - SQLite no tiene UUID nativo -> usamos String(36)
    # - Enum nativo no existe -> native_enum=False
    # ==========================================================
    op.create_table(
        "threats",
        # ✅ Antes: sa.UUID()
        sa.Column("id", sa.String(length=36), nullable=False),

        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),

        sa.Column("fingerprint", sa.String(length=512), nullable=True),

        # JSON: en SQLite se guarda como TEXT internamente (ok)
        sa.Column("siem_metadata", sa.JSON(), nullable=True),

        sa.Column(
            "category",
            sa.Enum(
                "performance",
                "availability",
                "network",
                "database",
                "auth",
                "other",
                name="threatcategory",
                native_enum=False,  # ✅ clave para SQLite
            ),
            nullable=True,
        ),

        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("target_service", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("database_name", sa.String(length=255), nullable=True),
        sa.Column("database_host", sa.String(length=255), nullable=True),

        sa.Column(
            "level",
            sa.Enum(
                "critical",
                "high",
                "medium",
                "low",
                name="threatlevel",
                native_enum=False,  # ✅ clave para SQLite
            ),
            nullable=False,
        ),

        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),

        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(op.f("ix_threats_fingerprint"), "threats", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_threats_id"), "threats", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_threats_id"), table_name="threats")
    op.drop_index(op.f("ix_threats_fingerprint"), table_name="threats")
    op.drop_table("threats")

    op.drop_index(op.f("ix_users_id"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")