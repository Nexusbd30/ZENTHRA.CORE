from __future__ import annotations

import secrets

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.secrets import get_secret
from app.core.settings import settings
from app.core.tenant_context import current_tenant
from app.db.session import get_db
from app.models.user import User


def _assert_payload_tenant(value, tenant):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "tenant_id" and item and item != tenant:
                raise HTTPException(status_code=403, detail="Tenant membership mismatch")
            _assert_payload_tenant(item, tenant)
    elif isinstance(value, list):
        for item in value:
            _assert_payload_tenant(item, tenant)


async def request_scope(request: Request, db: Session = Depends(get_db)):
    tenant = settings.CONTROL_TOKEN_TENANT_ID or settings.DEFAULT_TENANT_ID
    bearer = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    monitor = get_secret("VAELQORIX_MONITOR_TOKEN", settings.VAELQORIX_MONITOR_TOKEN)
    control = get_secret("VAELQORIX_CONTROL_TOKEN", settings.VAELQORIX_CONTROL_TOKEN)
    is_monitor = bool(monitor and secrets.compare_digest(bearer, monitor))
    is_control = bool(control and secrets.compare_digest(bearer, control))
    if is_monitor and (request.url.path.startswith("/api/") or request.method not in {"GET", "HEAD"}):
        raise HTTPException(status_code=403, detail="Monitoring credentials are read-only")
    if is_control and monitor and secrets.compare_digest(control or "", monitor):
        raise HTTPException(status_code=403, detail="Control and monitoring credentials must differ")
    if not is_control:
        tenant = settings.DEFAULT_TENANT_ID
    if bearer and not (is_monitor or is_control):
        try:
            claims = jwt.decode(bearer, str(get_secret("SECRET_KEY", settings.SECRET_KEY) or ""), algorithms=["HS256"])
            user = db.query(User).filter(User.email == claims.get("sub")).first()
            if user is not None and user.is_active:
                tenant = user.tenant_id
        except jwt.InvalidTokenError:
            pass  # Endpoint authentication supplies its normal 401/403 response.
    if tenant != settings.DEFAULT_TENANT_ID and (
        request.url.path.startswith("/monitoring")
        or "/kill-switch" in request.url.path
        or request.url.path == "/users/runtime-logs"
    ):
        raise HTTPException(status_code=403, detail="Deployment-wide operations require the platform tenant")
    requested = request.headers.get("x-tenant-id")
    if requested is not None and requested.strip() != tenant:
        raise HTTPException(status_code=403, detail="Tenant membership mismatch")
    query_tenant = request.query_params.get("tenant_id")
    if query_tenant and query_tenant != tenant:
        raise HTTPException(status_code=403, detail="Tenant membership mismatch")
    if request.method in {"POST", "PUT", "PATCH"} and "application/json" in request.headers.get("content-type", ""):
        try:
            payload = await request.json()
        except ValueError:
            payload = None
        _assert_payload_tenant(payload, tenant)
    # Login must find the account before its persisted tenant is known (email is unique).
    scoped = request.url.path != "/auth/login"
    token = current_tenant.set(tenant if scoped else None)
    if scoped:
        if hasattr(db, "info"):
            db.info["tenant_id"] = tenant
    request.state.tenant_id = tenant
    try:
        yield
    finally:
        if hasattr(db, "info"):
            db.info.pop("tenant_id", None)
        current_tenant.reset(token)
