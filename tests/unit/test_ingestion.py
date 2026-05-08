import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_ingestion_normalizes_siem_event(test_client, monkeypatch):
    resp = await test_client.post(
        "/api/v1/ingestion/normalize",
        headers=monitor_headers(monkeypatch),
        json={
            "source": "wazuh/edr",
            "alertname": "CredentialStuffing",
            "severity": "high",
            "target": "identity-api",
            "source_ip": "10.1.2.3",
            "labels": {"job": "wazuh", "alertname": "CredentialStuffing"},
            "annotations": {"summary": "Credential stuffing burst"},
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["level"] == "high"
    assert body["category"] == "other"
    assert body["target_service"] == "identity-api"
    assert body["fingerprint"]


@pytest.mark.asyncio
async def test_ingestion_creates_and_dedupes_threat_by_fingerprint(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    payload = {
        "source": "iam",
        "alertname": "ImpossibleTravel",
        "severity": "critical",
        "target": "user@example.com",
        "source_ip": "203.0.113.10",
        "fingerprint": "iam|ImpossibleTravel|user@example.com",
        "event": {"user": "user@example.com", "source_ip": "203.0.113.10"},
    }

    first = await test_client.post("/api/v1/ingestion/events", headers=headers, json=payload)
    second = await test_client.post("/api/v1/ingestion/events", headers=headers, json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()
    assert first_body["status"] == "created"
    assert second_body["status"] == "updated"
    assert second_body["threat_id"] == first_body["threat_id"]
    assert second_body["occurrences"] == 2
    assert second_body["threat"]["level"] == "critical"
    assert second_body["threat"]["category"] == "auth"
