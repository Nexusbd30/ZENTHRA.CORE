import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_health_endpoint(test_client):
    resp = await test_client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ready_endpoint(test_client):
    resp = await test_client.get("/ready")
    assert resp.status_code in (200, 503)


@pytest.mark.asyncio
async def test_system_health_router(test_client):
    resp = await test_client.get("/system/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "overall" in data


@pytest.mark.asyncio
async def test_ingestion_stub_status(test_client):
    resp = await test_client.get("/api/v1/ingestion/status")
    assert resp.status_code == 200
    assert resp.json()["module"] == "ingestion"


@pytest.mark.asyncio
async def test_redqueen_stub_status(test_client, monkeypatch):
    resp = await test_client.get(
        "/api/v1/redqueen/status",
        headers=monitor_headers(monkeypatch),
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "brain"


@pytest.mark.asyncio
async def test_ares_stub_status(test_client, monkeypatch):
    resp = await test_client.get(
        "/api/v1/ares/status",
        headers=monitor_headers(monkeypatch),
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "executor"


@pytest.mark.asyncio
async def test_redqueen_policy_matrix(test_client, monkeypatch):
    resp = await test_client.post(
        "/api/v1/redqueen/policy/evaluate?score=97&action_type=ot_shutdown",
        headers=monitor_headers(monkeypatch),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["requires_human"] is True
    assert data["allowed"] is False
    assert data["code"] == "action_unknown"


@pytest.mark.asyncio
async def test_redqueen_policy_matrix_requires_human_above_autonomy_threshold(
    test_client,
    monkeypatch,
):
    resp = await test_client.post(
        "/api/v1/redqueen/policy/evaluate?score=88&action_type=identity_lockdown",
        headers=monitor_headers(monkeypatch),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is True
    assert data["requires_human"] is True
    assert data["code"] == "human_required"
