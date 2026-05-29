from __future__ import annotations

import json

import pytest

from app.core.settings import settings
from app.models.audit_record import AuditRecord
from app.models.verdict import Verdict


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_redqueen_issues_verdict_from_aresx_threat_event(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    ingest = await test_client.post(
        "/api/v1/ingest/event",
        headers=headers,
        json={
            "source": "qradar",
            "payload": {
                "id": "offense-9001",
                "description": "Credential access T1110 followed by T1003",
                "magnitude": 9,
                "username": "alice@corp.com",
                "source_ip": "10.0.0.5",
            },
        },
    )
    assert ingest.status_code == 202
    event_id = ingest.json()["aresx_id"]

    response = await test_client.post(
        f"/api/v1/redqueen/verdict/from-event/{event_id}",
        headers=headers,
        json={"execution_controls": {"dry_run": True}},
    )

    assert response.status_code == 200
    body = response.json()
    verdict_payload = body["verdict"]
    assert body["status"] == "ok"
    assert body["event_id"] == event_id
    assert body["risk"]["scoring_model"] == "redqueen.aresx_event_rules.v1"
    assert body["perception"]["entity_id"] == "user:alice@corp.com"
    assert body["perception"]["risk_level"] in {"high", "critical"}
    assert verdict_payload["threat_event_id"] == event_id
    assert verdict_payload["recommended_actions"][0]["target"] == "user:alice@corp.com"
    assert verdict_payload["xai_explanation"]["method"] == "heuristic"
    assert verdict_payload["signature"]

    stored = db_session.query(Verdict).filter_by(verdict_id=verdict_payload["verdict_id"]).first()
    assert stored is not None
    assert stored.threat_event_id == event_id
    assert stored.primary_action == verdict_payload["action_type"]
    assert json.loads(stored.recommended_actions)[0]["target"] == "user:alice@corp.com"

    audit = (
        db_session.query(AuditRecord)
        .filter_by(verdict_id=verdict_payload["verdict_id"], event_type="aresx_verdict_emitted")
        .first()
    )
    assert audit is not None
    assert audit.chain_hash


@pytest.mark.asyncio
async def test_redqueen_from_event_returns_not_found(test_client, monkeypatch):
    response = await test_client.post(
        "/api/v1/redqueen/verdict/from-event/not-present",
        headers=monitor_headers(monkeypatch),
        json={},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "not_found", "event_id": "not-present"}
