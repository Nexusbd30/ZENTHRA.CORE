from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core import security
from app.core.settings import settings


def test_security_token_user_and_role_paths(monkeypatch, db_session):
    class SecretValue:
        def get_secret_value(self):
            return "secret-for-test"

    monkeypatch.setattr(settings, "SECRET_KEY", SecretValue())
    token = security.create_access_token({"sub": "admin@example.com"}, expires_delta=timedelta(minutes=1))

    assert security.get_bearer_token(f"Bearer {token}") == token
    with pytest.raises(HTTPException) as missing_bearer:
        security.get_bearer_token("")
    assert missing_bearer.value.status_code == 401

    monkeypatch.setattr(
        security.UserService,
        "get_user_by_email",
        lambda db, email: SimpleNamespace(email=email, role="admin", is_active=True),
    )
    user = security.get_current_user(token, db_session)
    assert user.email == "admin@example.com"
    assert security.get_current_active_user(user) is user
    assert security.get_current_admin(user) is user
    assert security.require_roles("admin")(user) is user

    with pytest.raises(HTTPException) as no_subject:
        security.get_current_user(
            security.create_access_token({"role": "admin"}, expires_delta=timedelta(minutes=1)),
            db_session,
        )
    assert no_subject.value.status_code == 401

    with pytest.raises(HTTPException) as bad_token:
        security.get_current_user("bad.jwt.token", db_session)
    assert bad_token.value.status_code == 401

    monkeypatch.setattr(security.UserService, "get_user_by_email", lambda db, email: None)
    with pytest.raises(HTTPException) as missing_user:
        security.get_current_user(token, db_session)
    assert missing_user.value.status_code == 401

    inactive = SimpleNamespace(role="admin", is_active=False)
    with pytest.raises(HTTPException) as inactive_error:
        security.get_current_active_user(inactive)
    assert inactive_error.value.status_code == 403

    analyst = SimpleNamespace(role="analyst", is_active=True)
    with pytest.raises(HTTPException) as admin_error:
        security.get_current_admin(analyst)
    assert admin_error.value.status_code == 403

    with pytest.raises(HTTPException) as role_error:
        security.require_roles("admin")(analyst)
    assert role_error.value.status_code == 403


def test_admin_or_monitor_and_enterprise_capability_paths(monkeypatch, db_session):
    monkeypatch.setattr(settings, "SECRET_KEY", "secret-for-test")
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-token")

    with pytest.raises(HTTPException) as missing_auth:
        security.require_admin_or_monitor_token("", db_session)
    assert missing_auth.value.status_code == 401

    assert security.require_admin_or_monitor_token("Bearer monitor-token", db_session) == {
        "auth_type": "monitor_token",
        "role": "internal",
    }

    with pytest.raises(HTTPException) as invalid_monitor_mode:
        security.require_admin_or_monitor_token("Bearer invalid", db_session)
    assert invalid_monitor_mode.value.status_code == 403

    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", None)
    with pytest.raises(HTTPException) as invalid_jwt_no_monitor:
        security.require_admin_or_monitor_token("Bearer invalid", db_session)
    assert invalid_jwt_no_monitor.value.status_code == 401

    token = security.create_access_token({"sub": "admin@example.com"}, expires_delta=timedelta(minutes=1))
    monkeypatch.setattr(
        security.UserService,
        "get_user_by_email",
        lambda db, email: SimpleNamespace(email=email, role="admin", is_active=True),
    )
    user = security.require_admin_or_monitor_token(f"Bearer {token}", db_session)
    assert user.email == "admin@example.com"

    monkeypatch.setattr(security.UserService, "get_user_by_email", lambda db, email: None)
    with pytest.raises(HTTPException) as unknown_user:
        security.require_admin_or_monitor_token(f"Bearer {token}", db_session)
    assert unknown_user.value.status_code == 401

    monkeypatch.setattr(
        security.UserService,
        "get_user_by_email",
        lambda db, email: SimpleNamespace(email=email, role="user", is_active=True),
    )
    with pytest.raises(HTTPException) as non_admin:
        security.require_admin_or_monitor_token(f"Bearer {token}", db_session)
    assert non_admin.value.status_code == 403

    monkeypatch.setattr(
        security.UserService,
        "get_user_by_email",
        lambda db, email: SimpleNamespace(email=email, role="admin", is_active=False),
    )
    with pytest.raises(HTTPException) as inactive:
        security.require_admin_or_monitor_token(f"Bearer {token}", db_session)
    assert inactive.value.status_code == 403

    checker = security.require_enterprise_capability("soc:execute")
    internal_context = checker(
        auth_context={"auth_type": "monitor_token", "role": "internal"},
        x_tenant_id="tenant-1",
        x_request_id="req-1",
    )
    assert internal_context["tenant_id"] == "tenant-1"
    assert internal_context["request_id"] == "req-1"

    user_context = checker(
        auth_context=SimpleNamespace(email="lead@example.com", role="secops_lead"),
        x_tenant_id=None,
        x_request_id=None,
    )
    assert user_context["actor"] == "lead@example.com"

    monkeypatch.setattr(settings, "ENTERPRISE_TENANT_MODE", "strict")
    with pytest.raises(HTTPException) as strict_missing_tenant:
        checker(
            auth_context={"auth_type": "monitor_token", "role": "internal"},
            x_tenant_id=None,
            x_request_id="req-strict",
        )
    assert strict_missing_tenant.value.status_code == 400
    monkeypatch.setattr(settings, "ENTERPRISE_TENANT_MODE", "single_tenant")

    with pytest.raises(HTTPException) as missing_capability:
        checker(
            auth_context=SimpleNamespace(email="viewer@example.com", role="viewer"),
            x_tenant_id=None,
            x_request_id=None,
        )
    assert missing_capability.value.status_code == 403
