from __future__ import annotations

import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


async def deactivate(test_client, headers):
    response = await test_client.post(
        "/api/v1/ares/kill-switch/deactivate",
        headers=headers,
        json={"reason": "test cleanup", "actor": "pytest"},
    )
    assert response.status_code == 200, response.text
    return response


@pytest.mark.asyncio
async def test_aresx_kill_switch_state_activate_deactivate_and_audit(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    await deactivate(test_client, headers)

    initial = await test_client.get("/api/v1/ares/kill-switch", headers=headers)
    assert initial.status_code == 200
    assert initial.json()["kill_switch"]["active"] is False
    assert initial.json()["kill_switch"]["ares_enabled"] is True

    activated = await test_client.post(
        "/api/v1/ares/kill-switch/activate",
        headers=headers,
        json={"reason": "false positive storm", "actor": "soc-admin"},
    )
    assert activated.status_code == 200, activated.text
    active_state = activated.json()["kill_switch"]
    assert active_state["active"] is True
    assert active_state["kill_switch"] is True
    assert active_state["ares_enabled"] is False
    assert active_state["reason"] == "false positive storm"
    assert active_state["actor"] == "soc-admin"
    assert active_state["updated_at"]

    activation_audit = await test_client.get(
        "/api/v1/audit/records?verdict_id=kill-switch&event_type=kill_switch_activated",
        headers=headers,
    )
    assert activation_audit.status_code == 200
    assert activation_audit.json()["count"] >= 1
    assert activation_audit.json()["items"][0]["actor"] == "soc-admin"

    deactivated = await test_client.post(
        "/api/v1/ares/kill-switch/deactivate",
        headers=headers,
        json={"reason": "manual review complete", "actor": "soc-admin"},
    )
    assert deactivated.status_code == 200, deactivated.text
    inactive_state = deactivated.json()["kill_switch"]
    assert inactive_state["active"] is False
    assert inactive_state["ares_enabled"] is True
    assert inactive_state["reason"] == "manual review complete"

    deactivation_audit = await test_client.get(
        "/api/v1/audit/records?verdict_id=kill-switch&event_type=kill_switch_deactivated",
        headers=headers,
    )
    assert deactivation_audit.status_code == 200
    assert deactivation_audit.json()["count"] >= 1
    assert deactivation_audit.json()["items"][0]["actor"] == "soc-admin"


@pytest.mark.asyncio
async def test_aresx_kill_switch_blocks_event_lifecycle_execution(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    await deactivate(test_client, headers)

    ingest = await test_client.post(
        "/api/v1/ingest/event",
        headers=headers,
        json={
            "source": "qradar",
            "payload": {
                "id": "kill-switch-event-9001",
                "description": "Credential access T1110",
                "magnitude": 8,
                "username": "alice@corp.com",
            },
        },
    )
    assert ingest.status_code == 202, ingest.text

    activated = await test_client.post(
        "/api/v1/ares/kill-switch/activate",
        headers=headers,
        json={"reason": "pause autonomous actions", "actor": "soc-admin"},
    )
    assert activated.status_code == 200, activated.text
    try:
        lifecycle = await test_client.post(
            f"/api/v1/ares/lifecycle/from-event/{ingest.json()['aresx_id']}",
            headers=headers,
            json={"human_approved": True, "execution_controls": {"dry_run": True}},
        )
        assert lifecycle.status_code == 200, lifecycle.text
        assert lifecycle.json()["execution"]["status"] == "rejected"
        assert lifecycle.json()["execution"]["code"] == "kill_switch"
    finally:
        await deactivate(test_client, headers)

