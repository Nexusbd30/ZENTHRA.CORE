import pytest

from app.core.settings import settings


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_redqueen_issues_signed_verdict(test_client, monkeypatch):
    resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": "host-01",
            "risk_score": 72,
            "factors": ["anomaly_login", "suspicious_process"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "host-01"
    assert data["action_type"] in {
        "observe",
        "soar_delegate",
        "endpoint_isolate",
        "identity_lockdown",
        "network_isolate",
    }
    assert isinstance(data.get("signature"), str) and len(data["signature"]) > 20


@pytest.mark.asyncio
async def test_ares_lifecycle_requires_human_for_high_risk(test_client, monkeypatch):
    resp = await test_client.post(
        "/api/v1/ares/lifecycle",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration_pattern"],
            "human_approved": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"]["requires_human"] is True
    assert data["execution"]["status"] == "pending_human_approval"


@pytest.mark.asyncio
async def test_ares_execute_with_human_approval(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "srv-auth",
            "risk_score": 88,
            "factors": ["credential_stuffing"],
            "execution_controls": {"change_ticket": "TEST-ARES-001"},
        },
    )
    verdict = verdict_resp.json()

    execute_resp = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={"verdict": verdict, "human_approved": True},
    )
    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "executed"
    assert data["execution"]["status"] == "success"


@pytest.mark.asyncio
async def test_ares_rejects_when_kill_switch_enabled(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    _ = await test_client.post("/api/v1/ares/kill-switch/on", headers=headers)

    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={"target": "host-02", "risk_score": 60, "factors": ["bruteforce"]},
    )
    verdict = verdict_resp.json()

    execute_resp = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={"verdict": verdict, "human_approved": True},
    )
    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "rejected"
    assert data["code"] == "kill_switch"

    _ = await test_client.post("/api/v1/ares/kill-switch/off", headers=headers)


@pytest.mark.asyncio
async def test_ares_rejects_disruptive_action_without_traceability(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={"target": "srv-auth", "risk_score": 88, "factors": ["credential_stuffing"]},
    )
    verdict = verdict_resp.json()

    execute_resp = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={"verdict": verdict, "human_approved": True},
    )

    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "rejected"
    assert data["code"] == "execution_control_missing"
