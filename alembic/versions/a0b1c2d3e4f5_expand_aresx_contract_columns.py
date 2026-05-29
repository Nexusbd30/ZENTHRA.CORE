"""expand aresx contract columns

Revision ID: a0b1c2d3e4f5
Revises: a2b3c4d5e6f7
Create Date: 2026-05-14 00:00:00.000000

"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a0b1c2d3e4f5"
down_revision = "a2b3c4d5e6f7"
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
        sa.Column("event_id", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(), nullable=True),
        sa.Column("entity_id", sa.String(length=255), nullable=True),
        sa.Column("entity_type", sa.String(length=64), nullable=True),
        sa.Column("mitre_tags", sa.Text(), nullable=True),
        sa.Column("normalized_payload", sa.Text(), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("dst_ip", sa.String(length=64), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("geo_country", sa.String(length=64), nullable=True),
        sa.Column("geo_city", sa.String(length=120), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("is_duplicate", sa.Boolean(), nullable=True),
    ]:
        _add_column("threat_events", column)

    for column in [
        sa.Column("threat_event_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("recommended_actions", sa.Text(), nullable=True),
        sa.Column("primary_action", sa.String(length=64), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("xai_explanation", sa.Text(), nullable=True),
        sa.Column("requires_human_approval", sa.Boolean(), nullable=True),
        sa.Column("policy_rule", sa.String(length=255), nullable=True),
        sa.Column("ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    ]:
        _add_column("verdicts", column)

    for column in [
        sa.Column("action_type", sa.String(length=64), nullable=True),
        sa.Column("target_entity", sa.String(length=255), nullable=True),
        sa.Column("target_system", sa.String(length=120), nullable=True),
        sa.Column("pre_state", sa.Text(), nullable=True),
        sa.Column("post_state", sa.Text(), nullable=True),
        sa.Column("rollback_payload", sa.Text(), nullable=True),
        sa.Column("rl_reward", sa.Float(), nullable=True),
    ]:
        _add_column("execution_results", column)

    for column in [
        sa.Column("sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("event_type", sa.String(length=120), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("chain_hash", sa.String(length=64), nullable=True),
        sa.Column("previous_chain_hash", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
    ]:
        _add_column("audit_records", column)

    for column in [
        sa.Column("feature_stats", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("observed_mitre_tags", sa.Text(), nullable=True),
        sa.Column("is_whitelisted", sa.Boolean(), nullable=True),
        sa.Column("whitelist_reason", sa.Text(), nullable=True),
        sa.Column("event_count", sa.BigInteger(), nullable=True),
    ]:
        _add_column("entity_profiles", column)

    for column in [
        sa.Column("entity_id", sa.String(length=255), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
    ]:
        _add_column("risk_scores", column)


def downgrade() -> None:
    for table_name, column_names in {
        "risk_scores": ["risk_level", "risk_score", "entity_id"],
        "entity_profiles": [
            "event_count",
            "whitelist_reason",
            "is_whitelisted",
            "observed_mitre_tags",
            "risk_level",
            "risk_score",
            "feature_stats",
        ],
        "audit_records": [
            "signature",
            "payload",
            "previous_chain_hash",
            "chain_hash",
            "content_hash",
            "event_type",
            "sequence_number",
        ],
        "execution_results": [
            "rl_reward",
            "rollback_payload",
            "post_state",
            "pre_state",
            "target_system",
            "target_entity",
            "action_type",
        ],
        "verdicts": [
            "expires_at",
            "ttl_seconds",
            "policy_rule",
            "requires_human_approval",
            "xai_explanation",
            "confidence_score",
            "primary_action",
            "recommended_actions",
            "severity",
            "status",
            "threat_event_id",
        ],
        "threat_events": [
            "is_duplicate",
            "risk_score",
            "geo_city",
            "geo_country",
            "dst_port",
            "src_port",
            "dst_ip",
            "src_ip",
            "normalized_payload",
            "mitre_tags",
            "entity_type",
            "entity_id",
            "ingested_at",
            "occurred_at",
            "event_id",
        ],
    }.items():
        for column_name in column_names:
            _drop_column(table_name, column_name)
