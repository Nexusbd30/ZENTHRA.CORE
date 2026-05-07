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
            "execution_controls": {"change_ticket": "TEST-HUMAN-PENDING-001"},
            "human_approved": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"]["requires_human"] is True
    assert data["execution"]["status"] == "pending_human_approval"


@pytest.mark.asyncio
async def test_ares_rejects_human_boolean_without_signed_approval(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration"],
            "execution_controls": {"change_ticket": "TEST-APPROVAL-001"},
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
    assert data["status"] == "rejected"
    assert data["code"] == "approval_missing"


@pytest.mark.asyncio
async def test_ares_accepts_signed_human_approval_for_high_risk(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration"],
            "execution_controls": {"change_ticket": "TEST-APPROVAL-002"},
        },
    )
    verdict = verdict_resp.json()

    approval_resp = await test_client.post(
        "/api/v1/ares/approval-token",
        headers=headers,
        json={
            "verdict": verdict,
            "approver": "soc-lead",
            "reason": "approved containment in maintenance window",
        },
    )
    approval = approval_resp.json()

    execute_resp = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={
            "verdict": verdict,
            "human_approved": True,
            "approval_evidence": approval,
        },
    )

    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "executed"
    assert data["execution"]["status"] == "success"

    approvals_resp = await test_client.get(
        f"/api/v1/ares/approvals/{verdict['verdict_id']}",
        headers=headers,
    )
    approvals = approvals_resp.json()
    assert approvals["count"] == 1
    assert approvals["items"][0]["approver"] == "soc-lead"
    assert approvals["items"][0]["signature"] == approval["signature"]


@pytest.mark.asyncio
async def test_ares_rejects_approval_for_different_verdict(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    first_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration"],
            "execution_controls": {"change_ticket": "TEST-APPROVAL-003"},
        },
    )
    first_verdict = first_resp.json()
    approval_resp = await test_client.post(
        "/api/v1/ares/approval-token",
        headers=headers,
        json={"verdict": first_verdict, "approver": "soc-lead", "reason": "approve first"},
    )

    second_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration"],
            "execution_controls": {"change_ticket": "TEST-APPROVAL-004"},
        },
    )
    second_verdict = second_resp.json()

    execute_resp = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={
            "verdict": second_verdict,
            "human_approved": True,
            "approval_evidence": approval_resp.json(),
        },
    )

    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "rejected"
    assert data["code"] == "approval_verdict_mismatch"


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


@pytest.mark.asyncio
async def test_ares_rejects_mcp_blocked_action(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"network_isolate","confidence":0.95,'
            '"reasoning":"containment requested","factors":["llm_containment"]}'
        ),
    )

    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "critical-db",
            "risk_score": 97,
            "factors": ["data_exfiltration"],
            "execution_controls": {
                "change_ticket": "TEST-MCP-BLOCK-001",
                "mcp_context": {"blocked_actions": ["network_isolate"]},
            },
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
    assert data["status"] == "rejected"
    assert data["code"] == "mcp_action_blocked"


@pytest.mark.asyncio
async def test_ares_rejects_action_outside_mcp_allowlist(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"identity_lockdown","confidence":0.90,'
            '"reasoning":"identity containment requested","factors":["credential_stuffing"]}'
        ),
    )

    verdict_resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "srv-auth",
            "risk_score": 88,
            "factors": ["credential_stuffing"],
            "execution_controls": {
                "change_ticket": "TEST-MCP-ALLOW-001",
                "mcp_context": {"allowed_actions": ["observe", "soar_delegate"]},
            },
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
    assert data["status"] == "rejected"
    assert data["code"] == "mcp_action_not_allowed"
