from __future__ import annotations

from app.core.settings import settings
from app.identity.entra_graph import dispatch_entra_graph_command


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b"{}" if payload is not None else b""
        self.headers = {"request-id": "req-test-1"}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def configure_entra(monkeypatch):
    monkeypatch.setattr(settings, "ENTRA_TENANT_ID", "tenant-1")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_ID", "client-1")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_SECRET", "secret-1")
    monkeypatch.setattr(settings, "ENTRA_GRAPH_BASE_URL", "https://graph.test/v1.0")
    monkeypatch.setattr(settings, "ENTRA_GRAPH_TOKEN_URL", "https://login.test/token")
    monkeypatch.setattr(settings, "ENTRA_GRAPH_SCOPE", "https://graph.test/.default")
    monkeypatch.setattr(settings, "ACTION_TIMEOUT_SEC", 3)


def test_entra_graph_resolve_uses_client_credentials_and_graph_user_lookup(monkeypatch):
    configure_entra(monkeypatch)
    calls: list[tuple[str, str, dict]] = []

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["scope"] == "https://graph.test/.default"
        return FakeResponse(payload={"access_token": "token-1"})

    def fake_get(url, **kwargs):
        calls.append(("GET", url, kwargs))
        assert url == (
            "https://graph.test/v1.0/users/alice%40corp.com"
            "?$select=id,userPrincipalName,accountEnabled"
        )
        assert kwargs["headers"]["Authorization"] == "Bearer token-1"
        return FakeResponse(
            payload={
                "id": "graph-user-1",
                "userPrincipalName": "alice@corp.com",
                "accountEnabled": True,
            }
        )

    monkeypatch.setattr("app.identity.entra_graph.requests.post", fake_post)
    monkeypatch.setattr("app.identity.entra_graph.requests.get", fake_get)

    result = dispatch_entra_graph_command(
        command="identity.resolve",
        payload={"target": "user:alice@corp.com"},
    )

    assert [call[0] for call in calls] == ["POST", "GET"]
    assert result == {
        "mode": "entra_graph",
        "command": "identity.resolve",
        "status": "ok",
        "provider": "entra",
        "target": "alice@corp.com",
        "graph_user_id": "graph-user-1",
        "user_principal_name": "alice@corp.com",
        "account_enabled": True,
        "provider_evidence": {
            "kind": "identity_provider_graph_action",
            "provider": "entra",
            "command": "identity.resolve",
            "operation": "resolve_user",
            "graph_path": "users/alice%40corp.com?$select=id,userPrincipalName,accountEnabled",
            "http_status": 200,
            "provider_request_id": "req-test-1",
            "target_sha256": result["provider_evidence"]["target_sha256"],
            "recorded_at": result["provider_evidence"]["recorded_at"],
            "secrets_exposed": False,
        },
    }


def test_entra_graph_disable_credentials_patches_account_enabled(monkeypatch):
    configure_entra(monkeypatch)
    calls: list[tuple[str, str, dict]] = []

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        return FakeResponse(payload={"access_token": "token-1"})

    def fake_patch(url, **kwargs):
        calls.append(("PATCH", url, kwargs))
        assert url == "https://graph.test/v1.0/users/alice%40corp.com"
        assert kwargs["json"] == {"accountEnabled": False}
        return FakeResponse(status_code=204)

    monkeypatch.setattr("app.identity.entra_graph.requests.post", fake_post)
    monkeypatch.setattr("app.identity.entra_graph.requests.patch", fake_patch)

    result = dispatch_entra_graph_command(
        command="identity.disable_credentials",
        payload={"target": "user:alice@corp.com"},
    )

    assert [call[0] for call in calls] == ["POST", "PATCH"]
    assert result["mode"] == "entra_graph"
    assert result["operation"] == "accountEnabled=false"
    assert result["provider_evidence"]["http_status"] == 204
    assert result["provider_evidence"]["secrets_exposed"] is False


def test_entra_graph_require_mfa_fails_without_policy_bridge(monkeypatch):
    configure_entra(monkeypatch)
    monkeypatch.setattr(settings, "ENTRA_REQUIRE_MFA_POLICY_URL", None)
    monkeypatch.setattr(
        "app.identity.entra_graph.requests.post",
        lambda *args, **kwargs: FakeResponse(payload={"access_token": "token-1"}),
    )

    try:
        dispatch_entra_graph_command(
            command="identity.require_mfa",
            payload={"target": "user:alice@corp.com"},
        )
    except RuntimeError as exc:
        assert "ENTRA_REQUIRE_MFA_POLICY_URL" in str(exc)
    else:
        raise AssertionError("require_mfa must require an approved policy bridge")


def test_entra_graph_degrade_privileges_resolves_user_id_before_group_removal(monkeypatch):
    configure_entra(monkeypatch)
    monkeypatch.setattr(settings, "ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS", "group-admins,group-release")
    calls: list[tuple[str, str, dict]] = []

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        return FakeResponse(payload={"access_token": "token-1"})

    def fake_get(url, **kwargs):
        calls.append(("GET", url, kwargs))
        return FakeResponse(payload={"id": "graph-user-1", "userPrincipalName": "alice@corp.com"})

    def fake_delete(url, **kwargs):
        calls.append(("DELETE", url, kwargs))
        assert "members/graph-user-1/$ref" in url
        return FakeResponse(status_code=204)

    monkeypatch.setattr("app.identity.entra_graph.requests.post", fake_post)
    monkeypatch.setattr("app.identity.entra_graph.requests.get", fake_get)
    monkeypatch.setattr("app.identity.entra_graph.requests.delete", fake_delete)

    result = dispatch_entra_graph_command(
        command="identity.degrade_privileges",
        payload={"target": "user:alice@corp.com"},
    )

    assert [call[0] for call in calls] == ["POST", "GET", "DELETE", "DELETE"]
    assert result["graph_user_id"] == "graph-user-1"
    assert result["group_ids"] == ["group-admins", "group-release"]
    assert result["provider_evidence"]["kind"] == "identity_provider_graph_action_batch"
    assert len(result["provider_evidence"]["items"]) == 3
