from __future__ import annotations

import pytest

from app.core.settings import settings
from app.secops.tenant_policies import list_tenant_policies, upsert_tenant_policy


def test_tenant_policy_service_persists_provider_assignments(db_session):
    created = upsert_tenant_policy(
        db_session,
        tenant_id="tenant-alpha",
        name="alpha-default",
        condition_dsl="risk_score >= 80",
        action_allowed=["observe", "require_mfa", "observe"],
        provider_assignments={"identity": "entra", "devsecops": "github_actions"},
        max_autonomy_score=75,
        requires_human=True,
        enabled=True,
    )

    listed = list_tenant_policies(db_session, tenant_id="tenant-alpha")

    assert listed["count"] == 1
    assert listed["items"][0]["rule_id"] == created["rule_id"]
    assert listed["items"][0]["action_allowed"] == ["observe", "require_mfa"]
    assert listed["items"][0]["provider_assignments"] == {
        "devsecops": "github_actions",
        "identity": "entra",
    }


@pytest.mark.asyncio
async def test_tenant_policy_api_updates_and_readiness(test_client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    headers = {"Authorization": "Bearer monitor-test-token"}

    created = await test_client.post(
        "/api/v1/secops/tenant-policies",
        headers=headers,
        json={
            "tenant_id": "tenant-beta",
            "name": "beta-provider-policy",
            "condition_dsl": "provider == 'entra'",
            "action_allowed": ["require_mfa"],
            "provider_assignments": {"identity": "entra"},
            "max_autonomy_score": 60,
            "requires_human": True,
            "enabled": True,
        },
    )
    assert created.status_code == 200, created.text
    rule_id = created.json()["rule_id"]

    updated = await test_client.post(
        "/api/v1/secops/tenant-policies",
        headers=headers,
        json={
            "rule_id": rule_id,
            "tenant_id": "tenant-beta",
            "name": "beta-provider-policy",
            "condition_dsl": "provider == 'entra'",
            "action_allowed": ["require_mfa", "revoke_session"],
            "provider_assignments": {"identity": "entra"},
            "max_autonomy_score": 65,
            "requires_human": True,
            "enabled": True,
        },
    )
    assert updated.status_code == 200, updated.text

    listed = await test_client.get(
        "/api/v1/secops/tenant-policies?tenant_id=tenant-beta",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert listed.json()["items"][0]["action_allowed"] == ["require_mfa", "revoke_session"]

    readiness = await test_client.get(
        "/api/v1/secops/enterprise/readiness",
        headers={**headers, "X-Tenant-ID": "tenant-beta"},
    )
    assert readiness.status_code == 200
    assert readiness.json()["tenant_policy"]["strict_mode_ready"] is True
