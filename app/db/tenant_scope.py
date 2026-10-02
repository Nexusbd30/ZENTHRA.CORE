"""Apply tenant restrictions to ORM reads and writes, including legacy repositories."""
from fastapi import HTTPException
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session, with_loader_criteria

from app.core.tenant_context import current_tenant
from app.models.base import Base
from app.models.user import User


@event.listens_for(Session, "do_orm_execute")
def scope_statement(state):
    tenant = state.session.info.get("tenant_id") or current_tenant.get()
    if tenant is None:
        return  # Explicitly trusted maintenance/test session, outside HTTP requests.
    if state.is_select or state.is_update or state.is_delete:
        # Concrete models include the legacy models that declare their own tenant column.
        for mapper in Base.registry.mappers:
            model = mapper.class_
            state.statement = state.statement.options(
                with_loader_criteria(model, lambda cls: cls.tenant_id == tenant, include_aliases=True)
            )


@event.listens_for(Session, "before_flush")
def scope_writes(session, flush_context, instances):
    tenant = session.info.get("tenant_id") or current_tenant.get()
    if tenant is None:
        return
    for row in session.new | session.dirty | session.deleted:
        if not isinstance(row, Base):
            continue
        owner = getattr(row, "tenant_id", None)
        if row in session.new and owner is None:
            row.tenant_id = tenant
        elif owner != tenant and not (
            row in session.new and isinstance(row, User)
            and session.info.get("platform_provisioning") is True
        ):
            raise HTTPException(status_code=403, detail="Tenant ownership mismatch")
        elif row not in session.new and inspect(row).attrs.tenant_id.history.has_changes():
            raise HTTPException(status_code=403, detail="Tenant ownership is immutable")
        for column in inspect(type(row)).columns:
            for foreign_key in column.foreign_keys:
                parent = foreign_key.column.table
                value = getattr(row, column.key, None)
                if value is None or "tenant_id" not in parent.c:
                    continue
                owner = session.connection().execute(
                    parent.select().with_only_columns(parent.c.tenant_id).where(foreign_key.column == value)
                ).scalar_one_or_none()
                if owner is not None and owner != tenant:
                    raise HTTPException(status_code=403, detail="Cross-tenant relationship denied")
