from __future__ import annotations

from urllib.parse import quote

import pytest

from app.core.settings import settings
from app.db.audit_store import append_audit_record


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


async def run_aresx_lifecycle(test_client, headers, *, event_id: str):
    ingest = await test_client.post(
        "/api/v1/ingest/event",
        headers=headers,
        json={
            "source": "qradar",
            "payload": {
                "id": event_id,
                "description": "Credential access T1110",
                "magnitude": 8,
                "username": "alice@corp.com",
            },
        },
    )
    assert ingest.status_code == 202, ingest.text
    lifecycle = await test_client.post(
        f"/api/v1/ares/lifecycle/from-event/{ingest.json()['aresx_id']}",
        headers=headers,
        json={"human_approved": True, "execution_controls": {"dry_run": True}},
    )
    assert lifecycle.status_code == 200, lifecycle.text
    return lifecycle.json()


@pytest.mark.asyncio
async def test_aresx_audit_records_verify_and_read(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    lifecycle = await run_aresx_lifecycle(test_client, headers, event_id="audit-api-9001")
    verdict_id = lifecycle["verdict"]["verdict_id"]

    records = await test_client.get(
        f"/api/v1/audit/records?verdict_id={verdict_id}",
        headers=headers,
    )
    verify = await test_client.post("/api/v1/audit/verify", headers=headers, json={})

    assert records.status_code == 200
    body = records.json()
    assert body["count"] >= 2
    assert {item["event_type"] for item in body["items"]} >= {
        "aresx_verdict_emitted",
        "execution_completed",
    }
    assert all(item["chain_hash"] for item in body["items"])
    assert all(item["content_hash"] for item in body["items"])
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert verify.json()["records_checked"] >= body["count"]

    record_id = body["items"][0]["record_id"]
    single = await test_client.get(f"/api/v1/audit/records/{record_id}", headers=headers)
    assert single.status_code == 200
    assert single.json()["record_id"] == record_id
    assert isinstance(single.json()["payload"], dict)


@pytest.mark.asyncio
async def test_aresx_audit_filters_and_entity_history(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    lifecycle = await run_aresx_lifecycle(test_client, headers, event_id="audit-api-9002")
    verdict_id = lifecycle["verdict"]["verdict_id"]
    entity_id = "user:alice@corp.com"

    filtered = await test_client.get(
        f"/api/v1/audit/records?verdict_id={verdict_id}&event_type=execution_completed",
        headers=headers,
    )
    entity = await test_client.get(
        f"/api/v1/audit/entity/{quote(entity_id, safe='')}",
        headers=headers,
    )

    assert filtered.status_code == 200
    assert filtered.json()["count"] == 1
    assert filtered.json()["items"][0]["event_type"] == "execution_completed"
    assert entity.status_code == 200
    assert entity.json()["entity_id"] == entity_id
    assert entity.json()["count"] >= 1


@pytest.mark.asyncio
async def test_aresx_audit_filters_enterprise_context(test_client, db_session, monkeypatch):
    append_audit_record(
        db_session,
        verdict_id="enterprise-audit-1",
        actor="ares",
        action="execution_completed",
        result={"status": "success"},
        actor_role="secops_lead",
        tenant_id="tenant-enterprise",
        capability="ares:execute",
        request_id="req-enterprise-1",
    )
    append_audit_record(
        db_session,
        verdict_id="enterprise-audit-2",
        actor="redqueen",
        action="verdict_issued",
        result={"status": "ok"},
        actor_role="analyst",
        tenant_id="tenant-other",
        capability="redqueen:read",
        request_id="req-enterprise-2",
    )

    response = await test_client.get(
        "/api/v1/audit/records?tenant_id=tenant-enterprise&capability=ares:execute",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    item = body["items"][0]
    assert item["verdict_id"] == "enterprise-audit-1"
    assert item["actor_role"] == "secops_lead"
    assert item["tenant_id"] == "tenant-enterprise"
    assert item["capability"] == "ares:execute"
    assert item["request_id"] == "req-enterprise-1"


@pytest.mark.asyncio
async def test_aresx_audit_missing_record_returns_not_found(test_client, monkeypatch):
    response = await test_client.get(
        "/api/v1/audit/records/not-present",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 200
    assert response.json() == {"status": "not_found", "record_id": "not-present"}
