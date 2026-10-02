# =============================================================
# 🧱 Base ORM — VAELQORIX.XDR_COMMAND
# =============================================================
# Punto central para la base declarativa de SQLAlchemy.
#
# - Todos los modelos deben heredar de `Base`.
# - Compatible con SQLAlchemy 2.x.
# =============================================================

from sqlalchemy import String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

from app.core.settings import settings
from app.core.tenant_context import current_tenant


class TenantOwned:
    tenant_id: Mapped[str] = mapped_column(
        String(120), nullable=False, index=True,
        default=lambda: current_tenant.get() or settings.DEFAULT_TENANT_ID,
    )

Base = declarative_base(cls=TenantOwned)
