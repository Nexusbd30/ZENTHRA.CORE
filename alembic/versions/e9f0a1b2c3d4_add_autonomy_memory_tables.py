"""add autonomy memory tables

Revision ID: e9f0a1b2c3d4
Revises: d7e8f9a0b1c2
Create Date: 2026-05-07 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e9f0a1b2c3d4"
down_revision = "d7e8f9a0b1c2"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return name in inspector.get_table_names()


def upgrade() -> None:
    if not _has_table("verdicts"):
        op.create_table(
            "verdicts",
            sa.Column("verdict_id", sa.String(length=36), nullable=False),
            sa.Column("timestamp", sa.DateTime(), nullable=False),
            sa.Column("target", sa.String(length=255), nullable=False),
            sa.Column("action_type", sa.String(length=64), nullable=False),
            sa.Column("risk_score", sa.Float(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("factors", sa.Text(), nullable=False),
            sa.Column("justification_xai", sa.Text(), nullable=False),
            sa.Column("policy_check", sa.Boolean(), nullable=False),
            sa.Column("requires_human", sa.Boolean(), nullable=False),
            sa.Column("execution_controls", sa.Text(), nullable=False),
            sa.Column("signature", sa.String(length=128), nullable=False),
            sa.PrimaryKeyConstraint("verdict_id"),
        )

    if not _has_table("execution_results"):
        op.create_table(
            "execution_results",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("verdict_id", sa.String(length=36), nullable=False),
            sa.Column("ares_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("duration_ms", sa.Integer(), nullable=False),
            sa.Column("evidence", sa.Text(), nullable=False),
            sa.Column("error_code", sa.String(length=64), nullable=False),
            sa.Column("result_hash", sa.String(length=128), nullable=False),
            sa.Column("timestamp", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_execution_results_verdict_id"),
            "execution_results",
            ["verdict_id"],
        )
        op.create_index(op.f("ix_execution_results_ares_id"), "execution_results", ["ares_id"])

    if not _has_table("risk_scores"):
        op.create_table(
            "risk_scores",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=64), nullable=False),
            sa.Column("score_0_100", sa.Float(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("factors", sa.Text(), nullable=False),
            sa.Column("timestamp", sa.DateTime(), nullable=False),
            sa.Column("trend", sa.String(length=24), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_risk_scores_asset_id"), "risk_scores", ["asset_id"])
        op.create_index(op.f("ix_risk_scores_timestamp"), "risk_scores", ["timestamp"])

    if not _has_table("entity_profiles"):
        op.create_table(
            "entity_profiles",
            sa.Column("entity_id", sa.String(length=64), nullable=False),
            sa.Column("entity_type", sa.String(length=32), nullable=False),
            sa.Column("baseline_vector", sa.Text(), nullable=False),
            sa.Column("anomaly_score", sa.Float(), nullable=False),
            sa.Column("last_seen", sa.DateTime(), nullable=False),
            sa.Column("risk_factors", sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint("entity_id"),
        )
        op.create_index(op.f("ix_entity_profiles_entity_type"), "entity_profiles", ["entity_type"])
        op.create_index(op.f("ix_entity_profiles_last_seen"), "entity_profiles", ["last_seen"])

    if not _has_table("policy_rules"):
        op.create_table(
            "policy_rules",
            sa.Column("rule_id", sa.String(length=36), nullable=False),
            sa.Column("condition_dsl", sa.Text(), nullable=False),
            sa.Column("action_allowed", sa.Text(), nullable=False),
            sa.Column("max_autonomy_score", sa.Float(), nullable=False),
            sa.Column("requires_human", sa.Boolean(), nullable=False),
            sa.PrimaryKeyConstraint("rule_id"),
        )


def downgrade() -> None:
    for table_name in [
        "policy_rules",
        "entity_profiles",
        "risk_scores",
        "execution_results",
        "verdicts",
    ]:
        if _has_table(table_name):
            op.drop_table(table_name)
