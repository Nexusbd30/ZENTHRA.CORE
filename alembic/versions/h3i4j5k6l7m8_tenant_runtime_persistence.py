"""Merge migration branches and persist tenant ownership, vectors and jobs.

Existing unscoped rows belong to the legacy default tenant. No tenant transfer
is inferred from historical caller-controlled headers or JSON payloads.
"""
import sqlalchemy as sa

from alembic import op

revision = "h3i4j5k6l7m8"
down_revision = ("c2d3e4f5a6b7", "g2h3i4j5k6l7")
branch_labels = None
depends_on = None

LEGACY_TABLES = (
    "users", "threats", "verdicts", "execution_results", "entity_profiles",
    "risk_scores", "threat_events", "approval_records", "response_logs", "knowledge_documents",
)


def upgrade():
    # Older releases created this table lazily; fresh databases must obtain it through migrations.
    if "knowledge_documents" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table("knowledge_documents",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("doc_id", sa.String(120), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("domain", sa.String(64), nullable=False),
            sa.Column("tags", sa.Text(), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("recommended_actions", sa.Text(), nullable=False),
            sa.Column("evidence_requirements", sa.Text(), nullable=False),
            sa.Column("source", sa.String(120), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("metadata_json", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("doc_id", "version", name="uq_knowledge_document_version"),
        )
        for column in ("doc_id", "version", "domain", "status", "content_hash"):
            op.create_index(f"ix_knowledge_documents_{column}", "knowledge_documents", [column])
    for table in LEGACY_TABLES:
        op.add_column(table, sa.Column("tenant_id", sa.String(120), nullable=False, server_default="default"))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    # Named convention permits rebuilding SQLite's initially unnamed primary key.
    with op.batch_alter_table("entity_profiles", naming_convention={"pk": "pk_%(table_name)s"}) as batch:
        pk_name = sa.inspect(op.get_bind()).get_pk_constraint("entity_profiles")["name"] or "pk_entity_profiles"
        batch.drop_constraint(pk_name, type_="primary")
        batch.create_primary_key("pk_entity_profiles", ["entity_id", "tenant_id"])
    with op.batch_alter_table("threat_events") as batch:
        existing = {item["name"] for item in sa.inspect(op.get_bind()).get_unique_constraints("threat_events")}
        if "uq_threat_events_source_event_id" in existing:
            batch.drop_constraint("uq_threat_events_source_event_id", type_="unique")
        batch.create_unique_constraint("uq_threat_events_source_event_id", ["tenant_id", "source", "event_id"])
    with op.batch_alter_table("audit_records") as batch:
        batch.create_unique_constraint("uq_audit_tenant_sequence", ["tenant_id", "sequence_number"])
    with op.batch_alter_table("knowledge_documents") as batch:
        batch.drop_constraint("uq_knowledge_document_version", type_="unique")
        batch.create_unique_constraint("uq_knowledge_document_version", ["tenant_id", "doc_id", "version"])
    op.create_table(
        "vector_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(120), nullable=False),
        sa.Column("collection", sa.String(120), nullable=False),
        sa.Column("record_id", sa.String(255), nullable=False),
        sa.Column("vector_json", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("tenant_id", "collection", "record_id", name="uq_vector_record"),
    )
    op.create_index("ix_vector_entries_tenant_id", "vector_entries", ["tenant_id"])
    op.create_index("ix_vector_entries_collection", "vector_entries", ["collection"])
    op.create_table(
        "runtime_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(120), nullable=False),
        sa.Column("queue", sa.String(120), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("queued_at", sa.DateTime(), nullable=False),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("lease_token", sa.String(36), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.UniqueConstraint("tenant_id", "queue", "idempotency_key", name="uq_runtime_job_key"),
    )
    for column in ("tenant_id", "queue", "status"):
        op.create_index(f"ix_runtime_jobs_{column}", "runtime_jobs", [column])


def downgrade():
    with op.batch_alter_table("audit_records") as batch:
        batch.drop_constraint("uq_audit_tenant_sequence", type_="unique")
    with op.batch_alter_table("entity_profiles") as batch:
        batch.drop_constraint("pk_entity_profiles", type_="primary")
        batch.create_primary_key("pk_entity_profiles", ["entity_id"])
    with op.batch_alter_table("threat_events") as batch:
        batch.drop_constraint("uq_threat_events_source_event_id", type_="unique")
        batch.create_unique_constraint("uq_threat_events_source_event_id", ["source", "event_id"])
    op.drop_table("runtime_jobs")
    op.drop_table("vector_entries")
    # Refuse an ambiguous downgrade when tenants reuse document IDs.
    with op.batch_alter_table("knowledge_documents") as batch:
        batch.drop_constraint("uq_knowledge_document_version", type_="unique")
        batch.create_unique_constraint("uq_knowledge_document_version", ["doc_id", "version"])
    for table in reversed(LEGACY_TABLES):
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_tenant_id")
            batch.drop_column("tenant_id")
