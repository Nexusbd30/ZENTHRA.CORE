from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_brain_lifecycle_connects_ingest_analysis_redqueen_and_ares(test_client, auth_token):
    response = await test_client.post(
        "/api/v1/brain/lifecycle",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "source": "qradar",
            "payload": {
                "id": "brain-event-1",
                "description": "Credential access T1110 from command center",
                "magnitude": 8,
                "username": "operator.demo@corp.local",
                "source_ip": "10.10.4.22",
            },
            "execution_controls": {
                "change_ticket": "BRAIN-DRY-RUN-1",
                "dns_firewall_provider": "sandbox",
            },
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["mode"] == "dry_run"
    assert data["ingest"]["status"] == "accepted"
    assert data["ingest"]["entity_id"] == "user:operator.demo@corp.local"
    assert data["analysis"]["entity_id"] == "user:operator.demo@corp.local"
    assert data["verdict"]["target"] == "user:operator.demo@corp.local"
    assert data["verdict"]["execution_controls"]["brain_lifecycle"] is True
    assert data["execution"]["status"] in {"executed", "pending_human_approval"}


@pytest.mark.asyncio
async def test_brain_status_exposes_layer_chain(test_client, auth_token):
    response = await test_client.get(
        "/api/v1/brain/status",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["module"] == "redqueen_brain"
    assert data["chain"] == [
        "aresx_ingest",
        "attack_analysis",
        "redqueen_verdict",
        "ares_validation",
        "ares_dry_run_execution",
        "evidence",
    ]
