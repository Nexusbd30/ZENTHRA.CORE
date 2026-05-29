from __future__ import annotations

from urllib.parse import quote

import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


async def run_lifecycle(test_client, headers, *, event_id: str):
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
async def test_aresx_redqueen_verdicts_profile_and_stats(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    lifecycle = await run_lifecycle(test_client, headers, event_id="ops-api-7001")
    verdict_id = lifecycle["verdict"]["verdict_id"]
    entity_id = "user:alice@corp.com"

    listing = await test_client.get("/api/v1/redqueen/verdicts?limit=5", headers=headers)
    detail = await test_client.get(f"/api/v1/redqueen/verdicts/{verdict_id}", headers=headers)
    profile = await test_client.get(
        f"/api/v1/redqueen/entities/{quote(entity_id, safe='')}/profile",
        headers=headers,
    )
    stats = await test_client.get("/api/v1/redqueen/stats", headers=headers)

    assert listing.status_code == 200
    assert any(item["verdict_id"] == verdict_id for item in listing.json()["items"])
    assert detail.status_code == 200
    assert detail.json()["verdict_id"] == verdict_id
    assert detail.json()["threat_event_id"] == lifecycle["verdict"]["threat_event_id"]
    assert detail.json()["recommended_actions"]
    assert isinstance(detail.json()["xai_explanation"], dict)
    assert profile.status_code == 200
    assert profile.json()["entity_id"] == entity_id
    assert profile.json()["baseline_vector"]
    assert stats.status_code == 200
    assert stats.json()["total_verdicts"] >= 1


@pytest.mark.asyncio
async def test_aresx_redqueen_approve_and_reject_verdict(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    lifecycle = await run_lifecycle(test_client, headers, event_id="ops-api-7002")
    verdict_id = lifecycle["verdict"]["verdict_id"]

    approved = await test_client.post(
        f"/api/v1/redqueen/verdicts/{verdict_id}/approve",
        headers=headers,
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["requires_human_approval"] is False

    rejected = await test_client.post(
        f"/api/v1/redqueen/verdicts/{verdict_id}/reject",
        headers=headers,
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


@pytest.mark.asyncio
async def test_aresx_executions_list_read_and_rollback(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    lifecycle = await run_lifecycle(test_client, headers, event_id="ops-api-7003")
    verdict_id = lifecycle["verdict"]["verdict_id"]

    listing = await test_client.get(
        f"/api/v1/ares/executions?verdict_id={verdict_id}",
        headers=headers,
    )
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    execution_id = listing.json()["items"][0]["id"]

    detail = await test_client.get(f"/api/v1/ares/executions/{execution_id}", headers=headers)

    assert listing.json()["items"][0]["id"] == execution_id
    assert detail.status_code == 200
    assert detail.json()["id"] == execution_id
    assert detail.json()["target_entity"] == "user:alice@corp.com"
    assert isinstance(detail.json()["pre_state"], dict)
    assert isinstance(detail.json()["post_state"], dict)

    rollback = await test_client.post(
        f"/api/v1/ares/executions/{execution_id}/rollback",
        headers=headers,
        json={"reason": "false positive confirmed", "actor": "soc-admin"},
    )
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["status"] == "rolled_back"
    assert rollback.json()["rollback_payload"]["reason"] == "false positive confirmed"
    assert rollback.json()["rl_reward"] == -0.4

    audit = await test_client.get(
        f"/api/v1/audit/records?verdict_id={verdict_id}&event_type=execution_rolled_back",
        headers=headers,
    )
    assert audit.status_code == 200
    assert audit.json()["count"] == 1
    assert audit.json()["items"][0]["actor"] == "soc-admin"
