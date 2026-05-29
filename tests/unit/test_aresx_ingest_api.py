from __future__ import annotations

import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_aresx_ingest_event_persists_and_dedupes_by_source_event_id(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    payload = {
        "source": "qradar",
        "payload": {
            "id": 4892,
            "description": "Brute force T1110 detected",
            "magnitude": 8,
            "username": "alice@corp.com",
            "source_ip": "10.0.0.5",
        },
    }

    first = await test_client.post("/api/v1/ingest/event", headers=headers, json=payload)
    second = await test_client.post("/api/v1/ingest/event", headers=headers, json=payload)

    assert first.status_code == 202
    assert second.status_code == 202
    first_body = first.json()
    second_body = second.json()
    assert first_body["status"] == "accepted"
    assert first_body["event_id"] == "4892"
    assert first_body["source"] == "qradar"
    assert first_body["severity"] == 8
    assert first_body["entity_id"] == "user:alice@corp.com"
    assert first_body["mitre_tags"] == ["T1110"]
    assert first_body["is_duplicate"] is False
    assert second_body["aresx_id"] == first_body["aresx_id"]
    assert second_body["is_duplicate"] is True


@pytest.mark.asyncio
async def test_aresx_ingest_batch_and_stats(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    batch = {
        "events": [
            {
                "source": "wazuh",
                "payload": {
                    "rule": {"id": "5710", "level": 10, "description": "Multiple failed ssh logins"},
                    "agent": {"name": "linux-prod-01"},
                    "data": {"srcip": "198.51.100.7"},
                },
            },
            {
                "source": "manual",
                "payload": {
                    "event_id": "manual-1",
                    "event_type": "anomaly",
                    "severity": "medium",
                    "target": "identity-api",
                },
            },
        ]
    }

    response = await test_client.post("/api/v1/ingest/batch", headers=headers, json=batch)
    stats = await test_client.get("/api/v1/ingest/stats", headers=headers)

    assert response.status_code == 202
    body = response.json()
    assert body["count"] == 2
    assert body["accepted"] == 2
    assert body["duplicates"] == 0
    assert {item["source"] for item in body["items"]} == {"wazuh", "manual"}
    assert stats.status_code == 200
    assert stats.json()["total"] >= 2


@pytest.mark.asyncio
async def test_aresx_ingest_webhook_and_sources(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)

    webhook = await test_client.post(
        "/api/v1/ingest/webhook/wazuh",
        headers=headers,
        json={
            "rule": {"id": "100001", "level": 14, "description": "Credential dump T1003"},
            "agent": {"name": "dc01"},
        },
    )
    sources = await test_client.get("/api/v1/ingest/sources", headers=headers)

    assert webhook.status_code == 202
    assert webhook.json()["source"] == "wazuh"
    assert webhook.json()["severity"] == 10
    assert "T1003" in webhook.json()["mitre_tags"]
    assert sources.status_code == 200
    assert "qradar" in sources.json()["adapters"]
    assert "manual" in sources.json()["sources"]
