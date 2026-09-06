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


@pytest.mark.asyncio
async def test_brain_chat_routes_aresx_order_as_dry_run(test_client, auth_token):
    response = await test_client.post(
        "/api/v1/brain/chat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "message": "Analyze this ARESX event and prepare ARES order",
            "source": "qradar",
            "payload": {
                "id": "brain-chat-event-1",
                "description": "Suspicious credential access T1110",
                "magnitude": 8,
                "username": "chat.operator@corp.local",
            },
            "execution_controls": {"dry_run": False},
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "brain_lifecycle"
    assert data["safety_boundary"] == "dry_run_only"
    assert data["result"]["mode"] == "dry_run"
    assert data["result"]["verdict"]["execution_controls"]["dry_run"] is True
    assert data["result"]["verdict"]["execution_controls"]["brain_chat"] is True


@pytest.mark.asyncio
async def test_brain_chat_can_generate_redqueen_verdict(test_client, auth_token):
    response = await test_client.post(
        "/api/v1/brain/chat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "message": "RedQueen verdict for suspicious host",
            "target": "host:runner-01",
            "risk_score": 72,
            "factors": ["operator_requested"],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "redqueen_verdict"
    assert data["result"]["verdict"]["target"] == "host:runner-01"
    assert data["result"]["verdict"]["execution_controls"]["dry_run"] is True
