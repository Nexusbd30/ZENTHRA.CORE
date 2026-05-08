import requests

from app.services.prometheus_client import PrometheusClient


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_prometheus_query_returns_result_vector(monkeypatch):
    captured = {}

    def fake_get(url, params=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        captured["timeout"] = timeout
        return _FakeResponse(
            {
                "status": "success",
                "data": {"result": [{"metric": {"job": "api"}, "value": [1, "1"]}]},
            }
        )

    monkeypatch.setattr(requests, "get", fake_get)
    client = PrometheusClient(base_url="http://prometheus:9090/", timeout_sec=3)

    result = client.query("up")

    assert result == [{"metric": {"job": "api"}, "value": [1, "1"]}]
    assert captured["url"] == "http://prometheus:9090/api/v1/query"
    assert captured["params"] == {"query": "up"}
    assert captured["timeout"] == 3
    assert client.has_result("up") is True


def test_prometheus_query_returns_empty_on_upstream_error(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.Timeout("timeout")

    monkeypatch.setattr(requests, "get", fake_get)
    client = PrometheusClient(base_url="http://prometheus:9090", timeout_sec=1)

    assert client.query("up") == []
    assert client.has_result("up") is False


def test_prometheus_get_alerts_normalizes_and_filters_state(monkeypatch):
    def fake_get(url, timeout=None):
        return _FakeResponse(
            {
                "status": "success",
                "data": {
                    "alerts": [
                        {
                            "labels": {"alertname": "BackendDown", "service": "api"},
                            "annotations": {"summary": "API down"},
                            "state": "firing",
                            "activeAt": "2026-05-09T10:00:00Z",
                            "value": "1",
                        },
                        {
                            "labels": {"alertname": "DiskFull"},
                            "state": "pending",
                        },
                        "invalid",
                    ]
                },
            }
        )

    monkeypatch.setattr(requests, "get", fake_get)
    client = PrometheusClient(base_url="http://prometheus:9090")

    firing = client.get_alerts()
    all_alerts = client.get_alerts(state=None)

    assert firing == [
        {
            "labels": {"alertname": "BackendDown", "service": "api"},
            "annotations": {"summary": "API down"},
            "state": "firing",
            "activeAt": "2026-05-09T10:00:00Z",
            "value": "1",
        }
    ]
    assert len(all_alerts) == 2
    assert client.get_firing_alerts() == firing


def test_prometheus_alerts_return_empty_for_invalid_payload(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: _FakeResponse({"status": "error"}))

    client = PrometheusClient(base_url="http://prometheus:9090")

    assert client.get_alerts() == []


def test_prometheus_fingerprint_prefers_service_label():
    fingerprint = PrometheusClient.build_fingerprint(
        {
            "alertname": "BackendDown",
            "instance": "api:8000",
            "job": "backend",
            "service": "auth-api",
        },
        target_service="fallback",
    )

    assert fingerprint == "BackendDown|api:8000|backend|auth-api"
