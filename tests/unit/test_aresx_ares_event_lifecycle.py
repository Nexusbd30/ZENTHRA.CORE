from __future__ import annotations

import json

import pytest

from app.core.settings import settings
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


async def ingest_aresx_event(test_client, headers, *, severity=8, event_id="aresx-event-1"):
    response = await test_client.post(
        "/api/v1/ingest/event",
        headers=headers,
        json={
            "source": "qradar",
            "payload": {
                "id": event_id,
                "description": "Lateral movement T1021 and credential access T1110",
                "magnitude": severity,
                "username": "alice@corp.com",
                "source_ip": "10.0.0.5",
            },
        },
    )
    assert response.status_code == 202, response.text
    return response.json()


@pytest.mark.asyncio
async def test_ares_lifecycle_from_aresx_event_executes_dry_run(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    event = await ingest_aresx_event(
        test_client,
        headers,
        severity=9,
        event_id="aresx-dry-run-9001",
    )

    response = await test_client.post(
        f"/api/v1/ares/lifecycle/from-event/{event['aresx_id']}",
        headers=headers,
        json={
            "human_approved": True,
            "execution_controls": {"dry_run": True},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    verdict = body["verdict"]
    execution = body["execution"]
    assert body["status"] == "ok"
    assert body["event_id"] == event["aresx_id"]
    assert verdict["threat_event_id"] == event["aresx_id"]
    assert execution["status"] == "executed"
    assert execution["execution"]["mode"] == "dry_run"
    assert all(step["status"] == "planned" for step in execution["execution"]["executed_steps"])

    stored_verdict = db_session.query(Verdict).filter_by(verdict_id=verdict["verdict_id"]).first()
    stored_result = (
        db_session.query(ExecutionResult).filter_by(verdict_id=verdict["verdict_id"]).first()
    )
    assert stored_verdict is not None
    assert stored_verdict.threat_event_id == event["aresx_id"]
    assert stored_result is not None
    assert stored_result.action_type == verdict["action_type"]
    assert stored_result.target_entity == "user:alice@corp.com"
    assert json.loads(stored_result.rollback_payload) == {"rollback_events": []}
    assert stored_result.rl_reward == 1.0


@pytest.mark.asyncio
async def test_ares_lifecycle_from_aresx_event_respects_human_approval_gate(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    event = await ingest_aresx_event(
        test_client,
        headers,
        severity=10,
        event_id="aresx-needs-human-9002",
    )

    response = await test_client.post(
        f"/api/v1/ares/lifecycle/from-event/{event['aresx_id']}",
        headers=headers,
        json={"execution_controls": {"dry_run": True}},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["execution"]["status"] == "pending_human_approval"
    assert body["verdict"]["requires_human"] is True


@pytest.mark.asyncio
async def test_ares_lifecycle_from_event_returns_not_found(test_client, monkeypatch):
    response = await test_client.post(
        "/api/v1/ares/lifecycle/from-event/not-present",
        headers=monitor_headers(monkeypatch),
        json={},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "not_found", "event_id": "not-present"}
