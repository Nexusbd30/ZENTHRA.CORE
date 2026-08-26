"""add governed DNS firewall rules and executions

Revision ID: g2h3i4j5k6l7
Revises: f1a2b3c4d5e6
Create Date: 2026-08-26 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "g2h3i4j5k6l7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_firewall_rules",
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("normalized_target", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verdict_id", sa.String(length=36), nullable=False),
        sa.Column("change_ticket", sa.String(length=120), nullable=False),
        sa.Column("provider_rule_id", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("approved_by", sa.String(length=120), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("rule_id"),
        sa.UniqueConstraint(
            "tenant_id", "provider", "normalized_target", "status",
            name="uq_dns_firewall_active_target",
        ),
    )
    op.create_index("ix_dns_firewall_rules_tenant_id", "dns_firewall_rules", ["tenant_id"])
    op.create_index("ix_dns_firewall_rules_normalized_target", "dns_firewall_rules", ["normalized_target"])
    op.create_index("ix_dns_firewall_rules_provider", "dns_firewall_rules", ["provider"])
    op.create_index("ix_dns_firewall_rules_verdict_id", "dns_firewall_rules", ["verdict_id"])

    op.create_table(
        "dns_firewall_executions",
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("verdict_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("provider_request_id", sa.String(length=255), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("execution_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_dns_firewall_idempotency"),
    )
    op.create_index("ix_dns_firewall_executions_tenant_id", "dns_firewall_executions", ["tenant_id"])
    op.create_index("ix_dns_firewall_executions_rule_id", "dns_firewall_executions", ["rule_id"])
    op.create_index("ix_dns_firewall_executions_verdict_id", "dns_firewall_executions", ["verdict_id"])


def downgrade() -> None:
    op.drop_table("dns_firewall_executions")
    op.drop_table("dns_firewall_rules")
