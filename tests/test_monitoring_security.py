import pytest

from app.core.settings import settings


@pytest.mark.asyncio
async def test_monitoring_health_full_requires_bearer(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")

    resp = await test_client.get("/monitoring/health/full")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_monitoring_health_full_rejects_invalid_token(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")

    resp = await test_client.get(
        "/monitoring/health/full",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_monitoring_health_full_with_valid_token(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")

    resp = await test_client.get(
        "/monitoring/health/full",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["backend"] == "up"
    assert data["overall"] in ("up", "degraded", "down")
