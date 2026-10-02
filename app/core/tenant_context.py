"""Request tenant scope, derived from a persisted account, never a caller assertion."""
from contextvars import ContextVar

current_tenant: ContextVar[str | None] = ContextVar("current_tenant", default=None)
