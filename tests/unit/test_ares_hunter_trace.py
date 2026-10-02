from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.core.settings import settings
from app.models.threat_event import ThreatEvent


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_CONTROL_TOKEN", "control-test-token")
    monkeypatch.setattr(settings, "CONTROL_TOKEN_CAPABILITIES", ",".join(__import__("app.core.enterprise_security", fromlist=["ENTERPRISE_CAPABILITIES"]).ENTERPRISE_CAPABILITIES))
    return {"Authorization": "Bearer control-test-token"}


def add_hunt_event(
    db_session,
    *,
    event_id: str,
    entity_id: str,
    event_type: str,
    severity: int,
    markers: list[str],
    minutes: int = 0,
):
    event = ThreatEvent(
        source="edr:defender",
        event_id=event_id,
        occurred_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=minutes),
        event_type=event_type,
        severity=severity,
        entity_id=entity_id,
        entity_type="host",
        mitre_tags=json.dumps([item for item in markers if item.startswith("T")]),
        normalized_payload=json.dumps(
            {
                "stage": markers[0] if markers else "unknown",
                "signals": markers,
                "summary": f"{event_type} during hunter trace",
            }
        ),
        risk_score=severity * 10,
        src_ip="10.0.0.15",
        dst_ip="10.0.0.20",
    )
    db_session.add(event)
    db_session.commit()
    return event


@pytest.mark.asyncio
async def test_ares_status_exposes_hunter_trace(test_client, monkeypatch):
    response = await test_client.get("/api/v1/ares/status", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["hunter_trace"]["schema"] == "vaelqorix.ares.hunter_trace.v1"
    assert body["hunter_trace"]["safety_boundary"] == "owned_or_authorized_assets_only"


@pytest.mark.asyncio
async def test_ares_hunter_trace_builds_defensive_eviction_plan(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    target = "host:prod-runner-7"
    add_hunt_event(
        db_session,
        event_id="hunt-1",
        entity_id=target,
        event_type="scheduled_task_persistence",
        severity=8,
        markers=["persistence", "scheduled_task", "T1053"],
    )
    add_hunt_event(
        db_session,
        event_id="hunt-2",
        entity_id=target,
        event_type="remote_service_lateral_movement",
        severity=9,
        markers=["lateral_movement", "remote_service", "T1021"],
        minutes=2,
    )

    response = await test_client.post(
        "/api/v1/ares/hunter-trace",
        headers=headers,
        json={
            "target": target,
            "execution_controls": {"ctf_mode": True, "change_ticket": "HUNT-001"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "vaelqorix.ares.hunter_trace.v1"
    assert body["mode"] == "defensive_hunt_inside_owned_environment"
    assert body["presence_state"] == "persistent_presence_suspected"
    assert body["expulsion_readiness"] == "operator_gated"
    assert "no_external_counter_intrusion" in body["guardrails"]
    finding_types = {item["type"] for item in body["hunt_findings"]}
    assert {"persistence", "lateral_movement", "high_severity"} <= finding_types
    steps = {item["step"] for item in body["eviction_plan"]}
    assert "preserve_hunter_trace" in steps
    assert "remove_persistence" in steps
    assert "verify_eviction" in steps
    assert "ctf_replay_pack" in steps


@pytest.mark.asyncio
async def test_ares_hunter_trace_unknown_target_stays_evidence_only(
    test_client,
    monkeypatch,
):
    response = await test_client.get(
        "/api/v1/ares/hunter-trace",
        headers=monitor_headers(monkeypatch),
        params={"target": "host:missing"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["presence_state"] == "unknown"
    assert body["expulsion_readiness"] == "insufficient_evidence"
    assert len(body["eviction_plan"]) == 2
    assert all(step["requires_confirmation"] is False for step in body["eviction_plan"])
