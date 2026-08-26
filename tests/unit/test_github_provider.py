from __future__ import annotations

from app.core.settings import settings
from app.secops.github import dispatch_github_command


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = {"x-github-request-id": "gh-req-1"}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def configure_github(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_API_BASE_URL", "https://github.test")
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "gh-token")
    monkeypatch.setattr(settings, "ACTION_TIMEOUT_SEC", 3)


def github_payload():
    return {
        "target": "repository:vaelqorix/core-security",
        "provider": "github_actions",
        "pipeline": {
            "repository": "vaelqorix/core-security",
            "environment": "production",
            "artifact_id": "12345",
        },
        "finding": {"artifact_id": "12345"},
    }


def test_github_provider_resolves_repository(monkeypatch):
    configure_github(monkeypatch)
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer gh-token"
        return FakeResponse(payload={"visibility": "private", "default_branch": "main"})

    monkeypatch.setattr("app.secops.github.requests.get", fake_get)

    result = dispatch_github_command(
        command="devsecops.resolve_pipeline",
        payload=github_payload(),
    )

    assert calls[0][0] == "https://github.test/repos/vaelqorix/core-security"
    assert result["mode"] == "github_api"
    assert result["visibility"] == "private"
    assert result["provider_evidence"]["provider_request_id"] == "gh-req-1"
    assert result["provider_evidence"]["secrets_exposed"] is False


def test_github_provider_blocks_deployment_with_environment_gate(monkeypatch):
    configure_github(monkeypatch)
    calls = []

    def fake_put(url, **kwargs):
        calls.append((url, kwargs))
        assert kwargs["json"] == {"prevent_self_review": True, "wait_timer": 0}
        return FakeResponse(status_code=200)

    monkeypatch.setattr("app.secops.github.requests.put", fake_put)

    result = dispatch_github_command(
        command="devsecops.block_deployment",
        payload=github_payload(),
    )

    assert calls[0][0] == "https://github.test/repos/vaelqorix/core-security/environments/production"
    assert result["operation"] == "environment_protection_gate"
    assert result["provider_evidence"]["http_status"] == 200


def test_github_provider_quarantines_actions_artifact(monkeypatch):
    configure_github(monkeypatch)
    calls = []

    def fake_delete(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(status_code=204)

    monkeypatch.setattr("app.secops.github.requests.delete", fake_delete)

    result = dispatch_github_command(
        command="devsecops.quarantine_artifact",
        payload=github_payload(),
    )

    assert calls[0][0] == "https://github.test/repos/vaelqorix/core-security/actions/artifacts/12345"
    assert result["artifact_id"] == "12345"
    assert result["provider_evidence"]["operation"] == "delete_actions_artifact"
