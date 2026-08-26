from __future__ import annotations

import pytest

from app.core.settings import settings
from app.db.audit_store import append_audit_record
from app.models.threat_event import ThreatEvent


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def identity_payload(event_id: str = "secops-event-1"):
    return {
        "provider": "entra",
        "event_id": event_id,
        "event_type": "token_reuse",
        "identity_id": "devops@corp.com",
        "severity": 8,
        "mfa_present": False,
        "privileged": True,
        "token_reuse": True,
        "raw_payload": {"pipeline": "release"},
    }


def devsecops_payload(event_id: str = "devsecops-event-1"):
    return {
        "provider": "github_actions",
        "event_id": event_id,
        "event_type": "secret_leak",
        "pipeline_id": "release-prod",
        "run_id": "run-42",
        "repository": "vaelqorix/core-security",
        "branch": "main",
        "commit_sha": "abc123",
        "environment": "production",
        "actor_identity": "devops@corp.com",
        "severity": 8,
        "finding_count": 3,
        "critical_count": 1,
        "high_count": 1,
        "cvss_score": 9.4,
        "cve_ids": ["CVE-2026-0001"],
        "secret_detected": True,
        "privileged_actor": True,
        "production_target": True,
        "deployment_blocked": True,
        "raw_payload": {"scanner": "ghas", "workflow": "release.yml"},
    }


@pytest.mark.asyncio
async def test_secops_status_exposes_devsecops_control_plane(test_client, monkeypatch):
    response = await test_client.get("/api/v1/secops/status", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops"
    assert body["role"] == "devsecops_control_plane"
    assert "redqueen" in body["integrates"]
    assert body["phase"] == "identity-and-pipeline-defense-core"
    assert "devsecops_signal_ingestion" in body["devsecops_controls"]
    assert "identity_pipeline_correlation" in body["devsecops_controls"]
    assert "ares_execution_gate" in body["devsecops_controls"]


@pytest.mark.asyncio
async def test_secops_intelligence_status_exposes_rag_llm_mcp_core(test_client, monkeypatch):
    response = await test_client.get(
        "/api/v1/secops/intelligence/status",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "intelligence"
    assert body["mode"] == "local-defensive-core"
    assert body["rag"]["provider"] == "in_memory"
    assert body["rag"]["repository_contract"] == "vaelqorix.knowledge_repository.v1"
    assert body["rag"]["document_count"] >= 1
    assert "identity" in body["domains"]
    assert "devsecops" in body["domains"]
    assert body["llm"]["decision_schema"] == "redqueen.llm_decision.v1"
    assert body["llm"]["contract_enforced"] is True
    assert body["llm"]["governance"]["schema"] == "vaelqorix.llm_governance.v1"
    assert body["llm"]["governance"]["ares_execution_requires_approved_contract"] is True
    assert "llm_governance" in body["llm"]["governance"]["evidence_required"]
    assert "allowed_action_validation" in body["llm"]["fallback_guardrails"]
    assert body["mcp"]["context_schema"] == "vaelqorix.mcp_context.v1"
    assert body["mcp"]["tool_policy_schema"] == "vaelqorix.mcp_tool_policy.v1"
    assert "tool_results" in body["mcp"]["supported_fields"]
    assert "allowed_tools" in body["mcp"]["supported_fields"]
    registered_tools = {tool["name"]: tool for tool in body["mcp"]["registered_tools"]}
    assert registered_tools["identity.lookup"]["mode"] == "read"
    assert "block_deployment" in body["recommended_actions"]


@pytest.mark.asyncio
async def test_secops_security_events_exposes_sanitized_webhook_rejections(
    test_client,
    db_session,
    monkeypatch,
):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-soc",
        capability="identity:triage",
        request_id="req-soc-1",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "invalid_signature",
            "status_code": 401,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-security-event-1",
            "client_ip": "203.0.113.50",
            "payload_sha256": "abc123",
            "secrets_exposed": False,
        },
    )
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-other",
        capability="identity:triage",
        request_id="req-soc-2",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "replay_detected",
            "status_code": 409,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-security-event-2",
            "client_ip": "203.0.113.51",
            "payload_sha256": "def456",
            "secrets_exposed": False,
        },
    )

    response = await test_client.get(
        "/api/v1/secops/security/events?tenant_id=tenant-soc",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops_security_events"
    assert body["count"] == 1
    assert body["by_reason"] == {"invalid_signature": 1}
    assert body["by_provider"] == {"entra": 1}
    assert body["by_tenant"] == {"tenant-soc": 1}
    item = body["items"][0]
    assert item["event_type"] == "identity_entra_webhook_rejected"
    assert item["reason"] == "invalid_signature"
    assert item["status_code"] == 401
    assert item["source_event_id"] == "entra-security-event-1"
    assert item["payload_sha256"] == "abc123"
    assert item["secrets_exposed"] is False
    assert "signature" not in item
    assert "payload" not in item


@pytest.mark.asyncio
async def test_secops_security_events_export_contract_for_case_management(
    test_client,
    db_session,
    monkeypatch,
):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-export",
        capability="identity:triage",
        request_id="req-export-1",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "replay_detected",
            "status_code": 409,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-export-1",
            "client_ip": "203.0.113.52",
            "payload_sha256": "exporthash",
            "secrets_exposed": False,
        },
    )

    response = await test_client.post(
        "/api/v1/secops/security/events/export",
        headers=monitor_headers(monkeypatch),
        json={
            "destination": "microsoft_sentinel",
            "format": "soc_case.v1",
            "tenant_id": "tenant-export",
            "include_items": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops_security_export"
    assert body["contract"] == "soc_case.v1"
    assert body["destination"] == "microsoft_sentinel"
    assert body["ready_to_send"] is False
    assert body["secrets_exposed"] is False
    assert body["payload"]["case_type"] == "integration_security_abuse"
    assert body["payload"]["summary"]["by_reason"]["replay_detected"] == 1
    assert body["payload"]["items"][0]["payload_sha256"] == "exporthash"
    assert "signature" not in body["payload"]["items"][0]


@pytest.mark.asyncio
async def test_secops_security_events_export_sends_signed_webhook(
    test_client,
    db_session,
    monkeypatch,
):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-export-send",
        capability="identity:triage",
        request_id="req-export-send-1",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "invalid_signature",
            "status_code": 401,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-export-send-1",
            "client_ip": "203.0.113.60",
            "payload_sha256": "sendhash",
            "secrets_exposed": False,
        },
    )
    monkeypatch.setattr(settings, "SOC_WEBHOOK_URL", "https://soc.example/webhook")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_TOKEN", "soc-token")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_HMAC_SECRET", "soc-secret")
    calls = []

    class FakeResponse:
        status_code = 202

        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("app.secops.service.requests.post", fake_post)

    response = await test_client.post(
        "/api/v1/secops/security/events/export",
        headers=monitor_headers(monkeypatch),
        json={
            "destination": "generic_webhook",
            "format": "soc_case.v1",
            "tenant_id": "tenant-export-send",
            "include_items": True,
            "send": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ready_to_send"] is True
    assert body["delivery"]["status"] == "sent"
    assert body["delivery"]["http_status"] == 202
    assert body["delivery"]["signature"]["enabled"] is True
    assert body["delivery"]["secrets_exposed"] is False
    assert calls[0][0] == "https://soc.example/webhook"
    headers = calls[0][1]["headers"]
    assert headers["Authorization"] == "Bearer soc-token"
    assert headers["X-Vaelqorix-Signature"].startswith("sha256=")
    assert headers["X-Vaelqorix-Idempotency-Key"]


@pytest.mark.asyncio
async def test_secops_posture_marks_security_event_abuse_for_soc(
    test_client,
    db_session,
    monkeypatch,
):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-posture-abuse",
        capability="identity:triage",
        request_id="req-posture-abuse-1",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "rate_limit_exceeded",
            "status_code": 429,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-posture-abuse-1",
            "client_ip": "203.0.113.60",
            "payload_sha256": "ratehash",
            "secrets_exposed": False,
        },
    )

    response = await test_client.get("/api/v1/secops/posture", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["security_events"] >= 1
    assert body["security_event_summary"]["by_reason"]["rate_limit_exceeded"] >= 1
    assert body["security_event_summary"]["by_provider"]["entra"] >= 1
    controls = {item["key"]: item for item in body["controls"]}
    assert controls["security_event_monitoring"]["status"] == "attention"
    assert controls["security_event_monitoring"]["owner"] == "soc"


@pytest.mark.asyncio
async def test_secops_materializes_security_event_abuse_for_redqueen_ares(
    test_client,
    db_session,
    monkeypatch,
):
    for index in range(2):
        append_audit_record(
            db_session,
            verdict_id="identity:entra:webhook",
            actor="monitor_token",
            actor_role="internal",
            tenant_id="tenant-security-abuse",
            capability="identity:triage",
            request_id=f"req-security-abuse-{index}",
            action="identity_entra_webhook_rejected",
            result={
                "status": "rejected",
                "reason": "invalid_signature",
                "status_code": 401,
                "provider": "entra",
                "source": "identity:entra",
                "source_event_id": f"entra-security-abuse-{index}",
                "client_ip": "203.0.113.70",
                "payload_sha256": f"abusehash{index}",
                "secrets_exposed": False,
            },
        )

    response = await test_client.post(
        "/api/v1/secops/security/events/materialize",
        headers=monitor_headers(monkeypatch),
        json={"min_count": 2, "limit": 20},
    )
    duplicate = await test_client.post(
        "/api/v1/secops/security/events/materialize",
        headers=monitor_headers(monkeypatch),
        json={"min_count": 2, "limit": 20},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops_security_events"
    assert body["scanned_events"] >= 2
    assert body["materialized"] >= 1
    assert body["duplicates"] == 0
    item = next(
        item
        for item in body["items"]
        if item["tenant_id"] == "tenant-security-abuse"
        and item["provider"] == "entra"
        and item["reason"] == "invalid_signature"
    )
    assert item["status"] == "materialized"
    assert item["provider"] == "entra"
    assert item["reason"] == "invalid_signature"
    assert item["entity_id"] == "integration:entra:tenant-security-abuse"

    event = (
        db_session.query(ThreatEvent)
            .filter_by(
                source="secops:integration_security_abuse",
                event_type="integration_security_abuse",
                event_id=item["source_event_id"],
            )
            .one()
    )
    assert event.risk_score >= 70
    assert event.entity_type == "integration"
    assert "abusehash0" in event.normalized_payload
    assert "body" not in event.normalized_payload

    assert duplicate.status_code == 200
    duplicate_body = duplicate.json()
    assert duplicate_body["materialized"] == 0
    assert duplicate_body["duplicates"] >= 1


@pytest.mark.asyncio
async def test_secops_security_event_lifecycle_routes_abuse_through_redqueen_ares(
    test_client,
    monkeypatch,
    db_session,
):
    for index in range(3):
        append_audit_record(
            db_session,
            verdict_id="identity:entra:webhook",
            actor="monitor_token",
            actor_role="internal",
            tenant_id="tenant-security-lifecycle",
            capability="identity:triage",
            request_id=f"req-security-lifecycle-{index}",
            action="identity_entra_webhook_rejected",
            result={
                "status": "rejected",
                "reason": "replay_detected",
                "status_code": 409,
                "provider": "entra",
                "source": "identity:entra",
                "source_event_id": f"entra-security-lifecycle-{index}",
                "client_ip": "203.0.113.80",
                "payload_sha256": f"lifecyclehash{index}",
                "secrets_exposed": False,
            },
        )

    headers = monitor_headers(monkeypatch)
    materialize = await test_client.post(
        "/api/v1/secops/security/events/materialize",
        headers=headers,
        json={"min_count": 3, "limit": 20},
    )
    materialized_item = next(
        item
        for item in materialize.json()["items"]
        if item["tenant_id"] == "tenant-security-lifecycle"
        and item["provider"] == "entra"
        and item["reason"] == "replay_detected"
    )

    response = await test_client.post(
        f"/api/v1/secops/security/events/{materialized_item['source_event_id']}/lifecycle",
        headers=headers,
        json={
            "human_approved": True,
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "TEST-SECURITY-ABUSE-001",
                "mcp_context": {
                    "tools": ["pipeline.lookup", "identity.lookup"],
                    "evidence_refs": ["case-security-abuse-1"],
                },
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["security_event"]["source"] == "secops:integration_security_abuse"
    assert body["security_event"]["event_type"] == "integration_security_abuse"
    assert body["verdict"]["execution_controls"]["action_domain"] == "devsecops"
    assert body["verdict"]["execution_controls"]["devsecops_contract"] == (
        "secops_integration_security_abuse.v1"
    )
    assert body["verdict"]["execution_controls"]["devsecops_provider"] == "secops"
    assert "devsecops_signal:integration_security_abuse" in body["verdict"]["factors"]
    assert "devsecops_signal:automated_abuse_pattern" in body["verdict"]["factors"]
    assert "mcp:evidence:case-security-abuse-1" in body["verdict"]["factors"]
    assert body["execution"]["status"] == "executed"
    traces = [
        item
        for item in body["execution"]["result"]["evidence"]
        if item.get("kind") == "intelligence_trace"
    ]
    assert traces
    assert traces[0]["action_domain"] == "devsecops"
    assert traces[0]["mcp_context"]["evidence_refs"] == ["case-security-abuse-1"]


@pytest.mark.asyncio
async def test_secops_security_metrics_expose_soc_activity(
    test_client,
    monkeypatch,
    db_session,
):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor_token",
        actor_role="internal",
        tenant_id="tenant-security-metrics",
        capability="identity:triage",
        request_id="req-security-metrics-1",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "rate_limit_exceeded",
            "status_code": 429,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "entra-security-metrics-1",
            "client_ip": "203.0.113.90",
            "payload_sha256": "metricshash",
            "secrets_exposed": False,
        },
    )
    headers = monitor_headers(monkeypatch)
    materialize = await test_client.post(
        "/api/v1/secops/security/events/materialize",
        headers=headers,
        json={"min_count": 1, "limit": 20},
    )
    assert materialize.status_code == 200
    assert materialize.json()["materialized"] + materialize.json()["duplicates"] >= 1
    metrics = await test_client.get("/metrics", headers=headers)

    assert metrics.status_code == 200
    text = metrics.text
    assert "vaelqorix_soc_materializations_total" in text
    assert 'event_type="integration_security_abuse"' in text
    assert 'status="materialized"' in text or 'status="duplicate"' in text


@pytest.mark.asyncio
async def test_secops_enterprise_readiness_exposes_security_and_integration_gate(
    test_client,
    monkeypatch,
):
    response = await test_client.get(
        "/api/v1/secops/enterprise/readiness",
        headers={
            **monitor_headers(monkeypatch),
            "X-Tenant-ID": "tenant-alpha",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "enterprise_security"
    assert body["phase"] == "phase_1_points_1_2"
    assert body["tenant"]["tenant_id"] == "tenant-alpha"
    assert body["rbac"]["enabled"] is True
    assert "security:admin" in body["rbac"]["roles"]["admin"]
    assert "identity:triage" in body["rbac"]["roles"]["analyst"]
    assert body["audit"]["hash_chain"] == "enabled"
    assert body["audit"]["tenant_context"] == "persisted"
    assert body["audit"]["capability_context"] == "persisted"
    assert body["audit"]["capability_gate"] == "bound_to_identity_and_devsecops_mutations"
    assert body["audit"]["external_provider_evidence"] == "persisted_for_identity_webhook_events"
    assert "entra" in body["integrations"]["identity"]["preferred_available"]
    assert "github_actions" in body["integrations"]["devsecops"]["preferred_available"]
    assert body["integrations"]["siem_soc"]["coverage"] == "contract_ready"
    assert "soc:execute" in body["integrations"]["siem_soc"]["capabilities"]
    assert body["security_runtime"]["rate_limit_store"]["backend"] == "in_memory"
    assert body["security_runtime"]["replay_guard_store"]["backend"] == "in_memory"
    assert body["next_gate"] == "connect_first_live_identity_or_devsecops_provider"


@pytest.mark.asyncio
async def test_secops_provider_registry_and_preflight(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)

    providers = await test_client.get("/api/v1/secops/providers", headers=headers)
    jenkins = await test_client.get("/api/v1/secops/providers/jenkins", headers=headers)
    preflight = await test_client.post(
        "/api/v1/secops/providers/jenkins/preflight",
        headers=headers,
        json={"action_type": "quarantine_artifact"},
    )

    assert providers.status_code == 200
    provider_names = {item["provider"] for item in providers.json()}
    assert "github_actions" in provider_names
    assert "jenkins" in provider_names

    assert jenkins.status_code == 200
    assert "block_deployment" in jenkins.json()["actions"]
    assert "quarantine_artifact" not in jenkins.json()["actions"]

    assert preflight.status_code == 200
    assert preflight.json()["supported"] is False
    assert preflight.json()["recommended_action"] == "block_deployment"
    assert preflight.json()["adjusted"] is True
    assert preflight.json()["reason"] == "provider_capability_missing"


@pytest.mark.asyncio
async def test_secops_posture_reflects_identity_pipeline(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    await test_client.post("/api/v1/identity/events", headers=headers, json=identity_payload())
    await test_client.post(
        "/api/v1/identity/entities/devops@corp.com/triage",
        headers=headers,
        json={"execute": True, "human_approved": True, "execution_controls": {"dry_run": True}},
    )

    response = await test_client.get("/api/v1/secops/posture", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops"
    assert body["mode"] == "devsecops"
    assert body["identity_events"] >= 1
    assert body["correlation_events"] == 0
    assert body["provider_registry"]["identity"]["provider_count"] >= 1
    assert "identity_lockdown" in body["provider_registry"]["identity"]["actions"]
    assert body["provider_registry"]["devsecops"]["provider_count"] >= 1
    assert "block_deployment" in body["provider_registry"]["devsecops"]["actions"]
    controls = {item["key"]: item for item in body["controls"]}
    assert controls["identity_signal_ingestion"]["status"] == "ok"
    assert controls["devsecops_signal_ingestion"]["owner"] == "secops"
    assert controls["identity_pipeline_correlation"]["status"] == "attention"
    assert controls["redqueen_decision_gate"]["owner"] == "redqueen"
    assert controls["ares_execution_gate"]["owner"] == "ares"
    assert controls["security_event_monitoring"]["owner"] == "soc"
    assert controls["identity_provider_preflight"]["status"] == "ok"
    assert controls["devsecops_provider_preflight"]["status"] == "ok"


@pytest.mark.asyncio
async def test_secops_ingests_devsecops_signal_and_deduplicates(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)

    response = await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=devsecops_payload(),
    )
    duplicate = await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=devsecops_payload(),
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["source"] == "devsecops:github_actions"
    assert body["event_type"] == "secret_leak"
    assert body["entity_id"] == "repository:vaelqorix/core-security"
    assert body["entity_type"] == "repository"
    assert body["risk_score"] >= 90
    assert "secret_exposure" in body["signals"]
    assert "T1552" in body["mitre_tags"]
    assert duplicate.status_code == 202
    assert duplicate.json()["is_duplicate"] is True


@pytest.mark.asyncio
async def test_secops_signal_summary_and_posture_include_pipeline_telemetry(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=devsecops_payload("devsecops-event-2"),
    )

    summary = await test_client.get("/api/v1/secops/signals/summary", headers=headers)
    posture = await test_client.get("/api/v1/secops/posture", headers=headers)

    assert summary.status_code == 200
    summary_body = summary.json()
    assert summary_body["module"] == "secops"
    assert summary_body["count"] >= 1
    assert summary_body["risk_level"] == "critical"
    assert "github_actions" in summary_body["providers"]
    assert "vaelqorix/core-security" in summary_body["repositories"]
    assert "production" in summary_body["environments"]
    assert "production_target" in summary_body["signals"]

    assert posture.status_code == 200
    posture_body = posture.json()
    assert posture_body["devsecops_events"] >= 1
    assert posture_body["correlation_events"] == 0
    controls = {item["key"]: item for item in posture_body["controls"]}
    assert controls["devsecops_signal_ingestion"]["status"] == "ok"


@pytest.mark.asyncio
async def test_secops_lifecycle_routes_pipeline_signal_through_redqueen_and_ares(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)

    response = await test_client.post(
        "/api/v1/secops/lifecycle",
        headers=headers,
        json={
            "signal": devsecops_payload("devsecops-lifecycle-1"),
            "human_approved": True,
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "TEST-DEVSECOPS-001",
                "mcp_context": {
                    "tools": ["identity.lookup", "pipeline.lookup", "secret.rotation.status"],
                    "evidence_refs": ["case-devsecops-1"],
                },
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["devsecops_event"]["source"] == "devsecops:github_actions"
    assert body["verdict"]["action_type"] == "block_deployment"
    assert body["verdict"]["execution_controls"]["action_domain"] == "devsecops"
    assert "devsecops_secret_detected:true" in body["verdict"]["factors"]
    assert "devsecops_production_target:true" in body["verdict"]["factors"]
    assert "rag_ref:devsecops-secret-exposure" in body["verdict"]["factors"]
    assert "rag_context_present" in body["verdict"]["factors"]
    assert "mcp:tool:identity.lookup" in body["verdict"]["factors"]
    assert "mcp:evidence:case-devsecops-1" in body["verdict"]["factors"]
    assert "devsecops-secret-exposure" in body["verdict"]["execution_controls"]["rag_references"]
    assert "identity.lookup" in body["verdict"]["execution_controls"]["mcp_context"]["tools"]
    assert body["verdict"]["execution_controls"]["mcp_tool_policy"]["schema"] == (
        "vaelqorix.mcp_tool_policy.v1"
    )
    assert body["verdict"]["execution_controls"]["mcp_tool_policy"]["allowed"] is True
    assert body["verdict"]["execution_controls"]["llm_contract"]["schema"] == (
        "redqueen.llm_decision.v1"
    )
    assert body["verdict"]["execution_controls"]["llm_contract"]["domain"] == "devsecops"
    assert body["verdict"]["execution_controls"]["llm_final_action_source"] in {
        "guardrail",
        "llm",
    }
    assert body["verdict"]["execution_controls"]["llm_guardrail_decisions"]
    assert body["execution"]["status"] == "executed"
    traces = [
        item for item in body["execution"]["result"]["evidence"] if item.get("kind") == "intelligence_trace"
    ]
    assert traces
    assert traces[0]["action_domain"] == "devsecops"
    assert "devsecops-secret-exposure" in traces[0]["rag_references"]
    assert traces[0]["mcp_context"]["evidence_refs"] == ["case-devsecops-1"]
    assert traces[0]["mcp_tool_policy"]["schema"] == "vaelqorix.mcp_tool_policy.v1"
    assert traces[0]["llm_contract"]["schema"] == "redqueen.llm_decision.v1"
    assert traces[0]["llm_guardrail_decisions"]


@pytest.mark.asyncio
async def test_secops_correlates_identity_activity_with_pipeline_signal(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    await test_client.post(
        "/api/v1/identity/events",
        headers=headers,
        json=identity_payload("identity-correlation-1"),
    )
    await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=devsecops_payload("devsecops-correlation-1"),
    )

    correlation = await test_client.get(
        "/api/v1/secops/correlations/identity-pipeline/devops@corp.com",
        headers=headers,
    )
    lifecycle = await test_client.post(
        "/api/v1/secops/lifecycle",
        headers=headers,
        json={
            "signal": devsecops_payload("devsecops-correlation-lifecycle-1"),
            "human_approved": True,
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "TEST-DEVSECOPS-CORR-001",
            },
        },
    )

    assert correlation.status_code == 200
    body = correlation.json()
    assert body["correlated"] is True
    assert body["identity_activity"]["event_count"] >= 1
    assert body["devsecops_summary"]["count"] >= 1
    assert body["risk_level"] == "critical"
    assert body["recommended_action"] == "block_deployment"
    assert "secret_exposure" in body["signals"]

    assert lifecycle.status_code == 200
    verdict = lifecycle.json()["verdict"]
    assert "devsecops_identity_correlation:true" in verdict["factors"]
    assert "devsecops_identity_signal:privileged_identity" in verdict["factors"]


@pytest.mark.asyncio
async def test_secops_correlation_lifecycle_materializes_event_for_redqueen_ares(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    await test_client.post(
        "/api/v1/identity/events",
        headers=headers,
        json=identity_payload("identity-correlation-lifecycle-1"),
    )
    await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=devsecops_payload("devsecops-correlation-lifecycle-source-1"),
    )

    response = await test_client.post(
        "/api/v1/secops/correlations/identity-pipeline/devops@corp.com/lifecycle",
        headers=headers,
        json={
            "human_approved": True,
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "TEST-CORR-LIFECYCLE-001",
            },
        },
    )
    duplicate = await test_client.post(
        "/api/v1/secops/correlations/identity-pipeline/devops@corp.com/lifecycle",
        headers=headers,
        json={
            "human_approved": True,
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "TEST-CORR-LIFECYCLE-002",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["correlation"]["correlated"] is True
    assert body["correlation_event"]["source"] == "secops:identity_pipeline_correlation"
    assert body["correlation_event"]["event_type"] == "identity_pipeline_correlation"
    assert body["correlation_event"]["entity_id"] == "repository:vaelqorix/core-security"
    assert body["verdict"]["action_type"] == "block_deployment"
    assert body["verdict"]["execution_controls"]["action_domain"] == "devsecops"
    assert "devsecops_signal:identity_pipeline_correlation" in body["verdict"]["factors"]
    assert "rag_ref:identity-pipeline-correlation" in body["verdict"]["factors"]
    assert body["execution"]["status"] == "executed"

    assert duplicate.status_code == 200
    assert duplicate.json()["correlation_event"]["is_duplicate"] is True

    posture = await test_client.get("/api/v1/secops/posture", headers=headers)
    assert posture.status_code == 200
    posture_body = posture.json()
    assert posture_body["correlation_events"] >= 1
    controls = {item["key"]: item for item in posture_body["controls"]}
    assert controls["identity_pipeline_correlation"]["status"] == "ok"


@pytest.mark.asyncio
async def test_secops_materializes_recent_identity_pipeline_correlations_in_batch(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    identity_signal = identity_payload("identity-batch-correlation-1")
    identity_signal["identity_id"] = "release-admin@corp.com"
    pipeline_signal = devsecops_payload("devsecops-batch-correlation-1")
    pipeline_signal["actor_identity"] = "release-admin@corp.com"
    unrelated_signal = devsecops_payload("devsecops-batch-unrelated-1")
    unrelated_signal["actor_identity"] = "build-bot@corp.com"

    await test_client.post(
        "/api/v1/identity/events",
        headers=headers,
        json=identity_signal,
    )
    await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=pipeline_signal,
    )
    await test_client.post(
        "/api/v1/secops/signals",
        headers=headers,
        json=unrelated_signal,
    )

    response = await test_client.post(
        "/api/v1/secops/correlations/identity-pipeline/materialize",
        headers=headers,
        json={"min_score": 90, "limit": 20},
    )
    duplicate = await test_client.post(
        "/api/v1/secops/correlations/identity-pipeline/materialize",
        headers=headers,
        json={"min_score": 90, "limit": 20},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "secops"
    assert body["scanned_actors"] >= 2
    assert body["materialized"] >= 1
    assert body["skipped"] >= 1
    statuses = {item["actor_identity"]: item["status"] for item in body["items"]}
    assert statuses["release-admin@corp.com"] == "materialized"
    assert statuses["build-bot@corp.com"] == "not_correlated"

    duplicate_body = duplicate.json()
    assert duplicate.status_code == 200
    assert duplicate_body["materialized"] == 0
    assert duplicate_body["duplicates"] >= 1
