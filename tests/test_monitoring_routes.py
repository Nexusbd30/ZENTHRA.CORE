import hashlib
import json

import httpx
import pytest

from app.core.settings import settings
from app.routers import monitoring


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://test")
            response = httpx.Response(self.status_code, request=request, text=self.text or "error")
            raise httpx.HTTPStatusError("upstream error", request=request, response=response)

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, responses=None, exc=None, *args, **kwargs):
        self.responses = list(responses or [])
        self.exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, params=None):
        if self.exc is not None:
            raise self.exc
        if self.responses:
            return self.responses.pop(0)
        return _FakeResponse()


@pytest.mark.asyncio
async def test_monitoring_query_proxies_payload(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    fake_payload = {"status": "success", "data": {"result": [{"metric": {"job": "api"}}]}}
    monkeypatch.setattr(
        monitoring.httpx,
        "AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(responses=[_FakeResponse(payload=fake_payload)]),
    )

    resp = await test_client.get(
        "/monitoring/query?q=up",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json() == fake_payload


@pytest.mark.asyncio
async def test_monitoring_range_returns_502_on_network_error(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    monkeypatch.setattr(
        monitoring.httpx,
        "AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(exc=httpx.RequestError("boom")),
    )

    resp = await test_client.get(
        "/monitoring/range?q=up",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 502
    assert "Error de red en /range" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_monitoring_alerts_realtime_returns_empty_list_on_error(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    monkeypatch.setattr(
        monitoring.httpx,
        "AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(exc=httpx.RequestError("alertmanager down")),
    )

    resp = await test_client.get(
        "/monitoring/alerts/realtime",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_monitoring_windows_nics_returns_prometheus_labels(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    fake_payload = {
        "status": "success",
        "data": {
            "result": [
                {
                    "metric": {
                        "nic": "Ethernet",
                        "instance": "host.docker.internal:9182",
                        "job": "windows-exporter",
                    },
                    "value": [1, "123"],
                }
            ]
        },
    }
    monkeypatch.setattr(
        monitoring.httpx,
        "AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(responses=[_FakeResponse(payload=fake_payload)]),
    )

    resp = await test_client.get(
        "/monitoring/windows/nics",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["count"] == 1
    assert data["data"][0]["name"] == "Ethernet"


@pytest.mark.asyncio
async def test_monitoring_gpu_summary_returns_unavailable_when_no_exporter(test_client, monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    empty_payload = {"status": "success", "data": {"result": []}}
    monkeypatch.setattr(
        monitoring.httpx,
        "AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(
            responses=[_FakeResponse(payload=empty_payload) for _ in range(4)]
        ),
    )

    resp = await test_client.get(
        "/monitoring/gpu/summary",
        headers={"Authorization": "Bearer monitor-test-token"},
    )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is False
    assert data["utilization_percent"] is None


@pytest.mark.asyncio
async def test_alertmanager_hook_hashes_payload_from_localhost(test_client):
    payload = [{"status": "firing", "labels": {"alertname": "BackendDown"}}]

    resp = await test_client.post("/hooks/alertmanager", json=payload)

    assert resp.status_code == 200, resp.text
    data = resp.json()
    expected_hash = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert data["ok"] is True
    assert data["received"] == 1
    assert data["hash"] == expected_hash
