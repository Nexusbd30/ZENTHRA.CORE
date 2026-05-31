from __future__ import annotations

import pytest

from app.core.settings import settings
from app.core.signing import verify_payload_signature


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def _force_network_isolate(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"network_isolate","confidence":0.94,'
            '"reasoning":"contract test containment","factors":["contract_flow"]}'
        ),
    )


@pytest.mark.asyncio
async def test_redqueen_ares_contract_preserves_dry_run_evidence_and_audit(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    _force_network_isolate(monkeypatch)

    verdict_response = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "network:prod-segment",
            "risk_score": 94,
            "factors": ["lateral_movement", "credential_access"],
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "RQ-ARES-CONTRACT-001",
                "mcp_context": {"allowed_actions": ["network_isolate"]},
            },
        },
    )

    assert verdict_response.status_code == 200, verdict_response.text
    verdict = verdict_response.json()
    assert {
        "verdict_id",
        "timestamp",
        "target",
        "action_type",
        "risk_score",
        "requires_human",
        "policy_check",
        "execution_controls",
        "signature",
    } <= set(verdict)
    assert verdict["action_type"] == "network_isolate"
    assert verdict["requires_human"] is True
    assert verdict["policy_check"] is True
    assert verify_payload_signature(
        {key: value for key, value in verdict.items() if key != "signature"},
        verdict["signature"],
    )

    controls = verdict["execution_controls"]
    assert controls["dry_run"] is True
    assert controls["change_ticket"] == "RQ-ARES-CONTRACT-001"
    assert controls["redqueen_thinking_model"]["execution_boundary"] == (
        "redqueen_decides_ares_executes"
    )
    assert controls["llm_contract"]["schema"] == "redqueen.llm_decision.v1"
    assert controls["mcp_action_policy"]["allowed"] is True
    assert controls["mcp_tool_policy"]["allowed"] is True

    execution_response = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={"verdict": verdict, "human_approved": True},
    )

    assert execution_response.status_code == 200, execution_response.text
    execution = execution_response.json()
    assert execution["status"] == "executed"
    assert execution["execution"]["mode"] == "dry_run"
    assert execution["execution"]["status"] == "success"
    assert all(step["status"] == "planned" for step in execution["execution"]["executed_steps"])
    assert execution["result"]["verdict_id"] == verdict["verdict_id"]
    assert execution["result"]["action_type"] == "network_isolate"
    assert execution["result"]["target_entity"] == "network:prod-segment"
    assert execution["result"]["result_hash"]

    intelligence_traces = [
        item for item in execution["result"]["evidence"] if item.get("kind") == "intelligence_trace"
    ]
    assert len(intelligence_traces) == 1
    trace = intelligence_traces[0]
    assert trace["llm_contract"]["schema"] == "redqueen.llm_decision.v1"
    assert trace["mcp_action_policy"]["allowed"] is True
    assert trace["mcp_tool_policy"]["allowed"] is True
    assert "execution_boundary:ares_only" in trace["decision_factors"]

    results_response = await test_client.get(
        f"/api/v1/ares/results/{verdict['verdict_id']}",
        headers=headers,
    )
    assert results_response.status_code == 200, results_response.text
    results = results_response.json()
    assert results["count"] == 1
    assert results["items"][0]["status"] == "success"
    assert results["items"][0]["result_hash"] == execution["result"]["result_hash"]

    audit_response = await test_client.get(
        f"/api/v1/ares/audit?verdict_id={verdict['verdict_id']}",
        headers=headers,
    )
    assert audit_response.status_code == 200, audit_response.text
    audit_actions = {item["action"] for item in audit_response.json()["items"]}
    assert {"verdict_issued", "execution_completed"} <= audit_actions

    verify_response = await test_client.get("/api/v1/ares/audit/verify", headers=headers)
    assert verify_response.status_code == 200, verify_response.text
    assert verify_response.json()["valid"] is True


@pytest.mark.asyncio
async def test_redqueen_ares_contract_blocks_real_mode_without_signed_approval(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    _force_network_isolate(monkeypatch)

    verdict_response = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=headers,
        json={
            "target": "network:critical-core",
            "risk_score": 96,
            "factors": ["active_exfiltration"],
            "execution_controls": {
                "dry_run": False,
                "change_ticket": "RQ-ARES-CONTRACT-002",
            },
        },
    )
    assert verdict_response.status_code == 200, verdict_response.text
    verdict = verdict_response.json()
    assert verdict["requires_human"] is True

    execution_response = await test_client.post(
        "/api/v1/ares/execute",
        headers=headers,
        json={"verdict": verdict, "human_approved": True},
    )

    assert execution_response.status_code == 200, execution_response.text
    body = execution_response.json()
    assert body["status"] == "rejected"
    assert body["code"] == "approval_missing"
    assert body["verdict_id"] == verdict["verdict_id"]


def test_redqueen_ares_openapi_keeps_contract_entrypoints():
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/redqueen/verdict" in paths
    assert "/api/v1/ares/execute" in paths
    assert "/api/v1/ares/results/{verdict_id}" in paths
    assert "/api/v1/ares/audit" in paths
    assert "/api/v1/ares/audit/verify" in paths

    redqueen_schema = paths["/api/v1/redqueen/verdict"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    ares_schema = paths["/api/v1/ares/execute"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]

    assert redqueen_schema["$ref"].endswith("/VerdictRequest")
    assert ares_schema["$ref"].endswith("/ExecuteRequest")
    assert paths["/api/v1/ares/results/{verdict_id}"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["$ref"].endswith("/ExecutionResultsResponse")
