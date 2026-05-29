from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.core.rate_limit import reset_rate_limits
from app.core.replay_guard import reset_replay_guard
from app.core.settings import settings
from app.models.audit_record import AuditRecord
from app.models.threat_event import ThreatEvent


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def identity_payload(event_id: str = "idp-event-1"):
    return {
        "provider": "entra",
        "event_id": event_id,
        "event_type": "token_reuse",
        "identity_id": "alice@corp.com",
        "severity": 8,
        "ip_address": "203.0.113.10",
        "geo_country": "ES",
        "geo_city": "Madrid",
        "mfa_present": False,
        "privileged": True,
        "token_reuse": True,
        "raw_payload": {"riskEventType": "tokenReplay"},
    }


def signed_json_headers(
    monkeypatch,
    payload: dict,
    secret: str = "test-webhook-secret",
    timestamp: str | None = None,
):
    headers = monitor_headers(monkeypatch)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = timestamp or str(int(time.time()))
    signed_payload = f"{timestamp}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    headers["X-Zenthra-Signature"] = f"sha256={digest}"
    headers["X-Zenthra-Timestamp"] = timestamp
    headers["Content-Type"] = "application/json"
    return headers, body


@pytest.mark.asyncio
async def test_identity_event_ingest_persists_identity_threat_event(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)

    first = await test_client.post(
        "/api/v1/identity/events",
        headers=headers,
        json=identity_payload("entra-token-1"),
    )
    second = await test_client.post(
        "/api/v1/identity/events",
        headers=headers,
        json=identity_payload("entra-token-1"),
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    body = first.json()
    assert body["source"] == "identity:entra"
    assert body["entity_id"] == "user:alice@corp.com"
    assert body["entity_type"] == "user"
    assert body["risk_score"] >= 90
    assert "T1078" in body["mitre_tags"]
    assert "T1528" in body["mitre_tags"]
    assert second.json()["is_duplicate"] is True

    stored = db_session.query(ThreatEvent).filter_by(event_id="entra-token-1").first()
    assert stored is not None
    assert stored.source == "identity:entra"
    assert stored.risk_score == body["risk_score"]
    normalized = json.loads(stored.normalized_payload)
    assert normalized["identity_context"]["subject"] == {
        "identity_id": "alice@corp.com",
        "provider": "entra",
        "privileged": True,
    }
    assert normalized["identity_context"]["signals"] == [
        "privileged_identity",
        "token_reuse",
        "mfa_absent",
    ]
    assert normalized["provider_evidence"]["provider"] == "entra"
    assert normalized["provider_evidence"]["received_via"] == "identity_signal_api"
    assert normalized["provider_evidence"]["source_event_id"] == "entra-token-1"
    assert normalized["provider_evidence"]["secrets_exposed"] is False


@pytest.mark.asyncio
async def test_identity_lifecycle_runs_redqueen_ares_dry_run(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    prior = identity_payload("entra-lifecycle-prior")
    prior["event_type"] = "login_failure"
    prior["token_reuse"] = False
    await test_client.post("/api/v1/identity/events", headers=headers, json=prior)

    response = await test_client.post(
        "/api/v1/identity/lifecycle",
        headers=headers,
        json={
            "signal": identity_payload("entra-lifecycle-1"),
            "human_approved": True,
            "execution_controls": {"dry_run": True},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["identity_event"]["source"] == "identity:entra"
    assert body["verdict"]["target"] == "user:alice@corp.com"
    assert body["verdict"]["action_type"] == "identity_lockdown"
    assert "identity_signal:token_reuse" in body["verdict"]["factors"]
    assert "identity_mfa:absent" in body["verdict"]["factors"]
    assert any(
        item.startswith("identity_recent_events:") for item in body["verdict"]["factors"]
    )
    assert "identity_recent_event_type:login_failure" in body["verdict"]["factors"]
    assert "identity_recent_signal:mfa_absent" in body["verdict"]["factors"]
    assert any(
        item.startswith("identity_activity_risk_boost:") for item in body["verdict"]["factors"]
    )
    assert body["verdict"]["execution_controls"]["action_domain"] == "identity"
    assert body["verdict"]["execution_controls"]["minimum_action_type"] == "identity_lockdown"
    assert body["verdict"]["threat_event_id"] == body["identity_event"]["event_id"]
    assert body["execution"]["status"] == "executed"
    assert body["execution"]["execution"]["mode"] == "dry_run"
    assert {
        step["step"] for step in body["execution"]["execution"]["executed_steps"]
    } == {"resolve_identity", "disable_credentials", "force_mfa"}


@pytest.mark.asyncio
async def test_identity_provider_capability_discovery(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)

    response = await test_client.get("/api/v1/identity/providers", headers=headers)
    provider = await test_client.get("/api/v1/identity/providers/active-directory", headers=headers)
    missing = await test_client.get("/api/v1/identity/providers/unknown-idp", headers=headers)

    assert response.status_code == 200
    providers = response.json()["providers"]
    assert "entra" in {item["provider"] for item in providers}
    assert "active_directory" in {item["provider"] for item in providers}

    assert provider.status_code == 200
    body = provider.json()
    assert body["provider"] == "active_directory"
    assert "identity.degrade_privileges" in body["commands"]
    assert "degrade_privileges" in body["actions"]
    assert "identity_lockdown" not in body["actions"]

    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_entra_readiness_and_event_normalization(test_client, db_session, monkeypatch):
    reset_replay_guard()
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "test-webhook-secret")
    payload = {
        "id": "entra-risk-9001",
        "riskEventType": "tokenReplay",
        "riskLevel": "high",
        "riskState": "at_risk",
        "userPrincipalName": "alice@corp.com",
        "createdDateTime": "2026-05-27T08:30:00Z",
        "ipAddress": "198.51.100.8",
        "mfaSatisfied": False,
        "isPrivileged": True,
        "location": {"countryOrRegion": "ES", "city": "Madrid"},
    }
    headers, body_bytes = signed_json_headers(monkeypatch, payload)

    readiness = await test_client.get("/api/v1/identity/providers/entra/readiness", headers=headers)
    response = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        content=body_bytes,
    )

    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["provider"] == "entra"
    assert readiness_body["configured"] is True
    assert readiness_body["webhook_secret_configured"] is True
    assert readiness_body["normalizes_to"] == "identity_signal.v1"
    assert readiness_body["provider_evidence"]["persisted"] is True
    assert readiness_body["rate_limit"]["enabled"] is True
    assert readiness_body["rate_limit"]["scope"] == "tenant_id + client_ip + provider"
    assert readiness_body["replay_guard"]["enabled"] is True
    assert readiness_body["replay_guard"]["scope"] == "timestamp + signature + payload_sha256"
    assert readiness_body["signature"]["required"] is True
    assert readiness_body["signature"]["algorithm"] == "hmac-sha256"
    assert readiness_body["signature"]["timestamp_header"] == "X-Zenthra-Timestamp"
    assert readiness_body["signature"]["max_skew_seconds"] == 300
    assert readiness_body["secrets_exposed"] is False

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["source"] == "identity:entra"
    assert body["source_event_id"] == "entra-risk-9001"
    assert body["event_type"] == "token_reuse"
    assert body["entity_id"] == "user:alice@corp.com"
    assert body["risk_score"] >= 90
    stored = db_session.query(ThreatEvent).filter_by(event_id="entra-risk-9001").first()
    assert stored is not None
    normalized = json.loads(stored.normalized_payload)
    assert normalized["contract"] == "identity_signal.v1"
    assert normalized["provider"] == "entra"
    assert normalized["identity_context"]["signals"] == [
        "privileged_identity",
        "token_reuse",
        "mfa_absent",
    ]
    evidence = normalized["provider_evidence"]
    assert evidence["kind"] == "identity_provider_webhook"
    assert evidence["provider"] == "entra"
    assert evidence["source"] == "identity:entra"
    assert evidence["source_event_id"] == "entra-risk-9001"
    assert evidence["received_via"] == "signed_webhook"
    assert evidence["signature"]["verified"] is True
    assert evidence["signature"]["signed_payload"] == "timestamp.body"
    assert evidence["secrets_exposed"] is False
    assert evidence["payload_sha256"] in normalized["evidence_refs"][1]


@pytest.mark.asyncio
async def test_entra_event_rejects_invalid_signature(test_client, db_session, monkeypatch):
    reset_replay_guard()
    headers = monitor_headers(monkeypatch)
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "test-webhook-secret")

    response = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        json={
            "id": "entra-risk-invalid-signature",
            "riskEventType": "tokenReplay",
            "riskLevel": "high",
            "userPrincipalName": "alice@corp.com",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid Entra webhook signature"
    audit = (
        db_session.query(AuditRecord)
        .filter_by(event_type="identity_entra_webhook_rejected")
        .order_by(AuditRecord.sequence_number.desc())
        .first()
    )
    assert audit is not None
    payload = json.loads(audit.payload)
    assert payload["reason"] == "invalid_signature"
    assert payload["status_code"] == 401
    assert payload["source_event_id"] == "entra-risk-invalid-signature"
    assert payload["secrets_exposed"] is False
    assert audit.capability == "identity:triage"


@pytest.mark.asyncio
async def test_entra_event_rejects_stale_signature_timestamp(test_client, monkeypatch):
    reset_replay_guard()
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_MAX_SKEW_SEC", 300)
    payload = {
        "id": "entra-risk-stale-signature",
        "riskEventType": "tokenReplay",
        "riskLevel": "high",
        "userPrincipalName": "alice@corp.com",
    }
    stale_timestamp = str(int(time.time()) - 900)
    headers, body_bytes = signed_json_headers(
        monkeypatch,
        payload,
        timestamp=stale_timestamp,
    )

    response = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        content=body_bytes,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid Entra webhook signature"


@pytest.mark.asyncio
async def test_entra_event_rate_limit_rejects_excess_requests(test_client, db_session, monkeypatch):
    reset_rate_limits()
    reset_replay_guard()
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_RATE_LIMIT_WINDOW_SEC", 60)
    headers, first_body = signed_json_headers(
        monkeypatch,
        {
            "id": "entra-risk-rate-limit-1",
            "riskEventType": "tokenReplay",
            "riskLevel": "high",
            "userPrincipalName": "alice@corp.com",
        },
    )
    headers["X-Tenant-Id"] = "tenant-rate-limit"
    second_headers, second_body = signed_json_headers(
        monkeypatch,
        {
            "id": "entra-risk-rate-limit-2",
            "riskEventType": "tokenReplay",
            "riskLevel": "high",
            "userPrincipalName": "alice@corp.com",
        },
    )
    second_headers["X-Tenant-Id"] = "tenant-rate-limit"

    first = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        content=first_body,
    )
    second = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=second_headers,
        content=second_body,
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 429
    assert second.json()["detail"] == "Entra webhook rate limit exceeded"
    assert second.headers["Retry-After"]
    assert second.headers["X-RateLimit-Limit"] == "1"
    audit = (
        db_session.query(AuditRecord)
        .filter_by(event_type="identity_entra_webhook_rejected", tenant_id="tenant-rate-limit")
        .order_by(AuditRecord.sequence_number.desc())
        .first()
    )
    assert audit is not None
    payload = json.loads(audit.payload)
    assert payload["reason"] == "rate_limit_exceeded"
    assert payload["status_code"] == 429

    metrics = await test_client.get("/metrics", headers=monitor_headers(monkeypatch))
    assert metrics.status_code == 200
    assert "zenthra_security_webhook_rejections_total" in metrics.text
    assert 'reason="rate_limit_exceeded"' in metrics.text
    assert "zenthra_security_rate_limit_rejections_total" in metrics.text


@pytest.mark.asyncio
async def test_entra_event_replay_guard_rejects_same_signed_payload(
    test_client,
    db_session,
    monkeypatch,
):
    reset_rate_limits()
    reset_replay_guard()
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "test-webhook-secret")
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED", True)
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_REPLAY_TTL_SEC", 300)
    payload = {
        "id": "entra-risk-replay-1",
        "riskEventType": "tokenReplay",
        "riskLevel": "high",
        "userPrincipalName": "alice@corp.com",
    }
    headers, body_bytes = signed_json_headers(monkeypatch, payload)

    first = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        content=body_bytes,
    )
    second = await test_client.post(
        "/api/v1/identity/providers/entra/events",
        headers=headers,
        content=body_bytes,
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 409
    assert second.json()["detail"] == "Entra webhook replay detected"
    audit = (
        db_session.query(AuditRecord)
        .filter_by(event_type="identity_entra_webhook_rejected")
        .order_by(AuditRecord.sequence_number.desc())
        .first()
    )
    assert audit is not None
    payload = json.loads(audit.payload)
    assert payload["reason"] == "replay_detected"
    assert payload["status_code"] == 409
    assert payload["source_event_id"] == "entra-risk-replay-1"

    metrics = await test_client.get("/metrics", headers=monitor_headers(monkeypatch))
    assert metrics.status_code == 200
    assert "zenthra_security_replay_rejections_total" in metrics.text
    assert 'reason="replay_detected"' in metrics.text


@pytest.mark.asyncio
async def test_identity_activity_summary(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    first = identity_payload("entra-activity-1")
    first["event_type"] = "login_failure"
    first["token_reuse"] = False
    second = identity_payload("entra-activity-2")
    second["event_type"] = "privilege_escalation"
    second["token_reuse"] = False

    await test_client.post("/api/v1/identity/events", headers=headers, json=first)
    await test_client.post("/api/v1/identity/events", headers=headers, json=second)
    response = await test_client.get(
        "/api/v1/identity/entities/alice@corp.com/activity",
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"] == "user:alice@corp.com"
    assert body["event_count"] >= 2
    assert "login_failure" in body["event_types"]
    assert "privilege_escalation" in body["event_types"]
    assert "mfa_absent" in body["signals"]
    assert "entra" in body["providers"]
    assert body["risk_level"] == "critical"
    assert body["recommended_provider"] == "entra"
    assert body["recommended_action"] == "identity_lockdown"


@pytest.mark.asyncio
async def test_identity_event_timeline(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    first = identity_payload("entra-timeline-1")
    first["event_type"] = "login_failure"
    first["token_reuse"] = False
    second = identity_payload("entra-timeline-2")

    await test_client.post("/api/v1/identity/events", headers=headers, json=first)
    await test_client.post("/api/v1/identity/events", headers=headers, json=second)
    response = await test_client.get(
        "/api/v1/identity/entities/alice@corp.com/events?limit=5",
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"] == "user:alice@corp.com"
    assert body["count"] >= 2
    assert {"entra-timeline-1", "entra-timeline-2"} <= {
        item["source_event_id"] for item in body["items"]
    }
    token_event = next(item for item in body["items"] if item["source_event_id"] == "entra-timeline-2")
    assert token_event["provider"] == "entra"
    assert "token_reuse" in token_event["signals"]
    assert "raw_payload" not in token_event


@pytest.mark.asyncio
async def test_identity_triage_preview_and_execute_dry_run(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    first = identity_payload("entra-triage-1")
    first["event_type"] = "login_failure"
    first["token_reuse"] = False
    second = identity_payload("entra-triage-2")

    await test_client.post("/api/v1/identity/events", headers=headers, json=first)
    await test_client.post("/api/v1/identity/events", headers=headers, json=second)

    preview = await test_client.post(
        "/api/v1/identity/entities/alice@corp.com/triage",
        headers=headers,
        json={"execute": False},
    )
    execute = await test_client.post(
        "/api/v1/identity/entities/alice@corp.com/triage",
        headers=headers,
        json={"execute": True, "human_approved": True, "execution_controls": {"dry_run": True}},
    )
    missing = await test_client.post(
        "/api/v1/identity/entities/missing@corp.com/triage",
        headers=headers,
        json={},
    )

    assert preview.status_code == 200
    preview_body = preview.json()
    assert preview_body["status"] == "ok"
    assert preview_body["activity"]["entity_id"] == "user:alice@corp.com"
    assert preview_body["verdict"]["target"] == "user:alice@corp.com"
    assert "execution" not in preview_body
    assert "identity_activity_signal:mfa_absent" in preview_body["verdict"]["factors"]

    assert execute.status_code == 200
    execute_body = execute.json()
    assert execute_body["status"] == "ok"
    assert execute_body["execution"]["status"] == "executed"
    assert execute_body["execution"]["execution"]["mode"] == "dry_run"

    assert missing.status_code == 200
    assert missing.json() == {"status": "not_found", "entity_id": "user:missing@corp.com"}


@pytest.mark.asyncio
async def test_identity_provider_action_preflight(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)

    supported = await test_client.post(
        "/api/v1/identity/providers/entra/preflight",
        headers=headers,
        json={"action_type": "identity_lockdown", "risk_score": 95},
    )
    adjusted = await test_client.post(
        "/api/v1/identity/providers/active-directory/preflight",
        headers=headers,
        json={"action_type": "identity_lockdown", "risk_score": 95},
    )
    missing = await test_client.post(
        "/api/v1/identity/providers/unknown-idp/preflight",
        headers=headers,
        json={"action_type": "identity_lockdown", "risk_score": 95},
    )

    assert supported.status_code == 200
    assert supported.json() == {
        "provider": "entra",
        "action_type": "identity_lockdown",
        "supported": True,
        "recommended_action": "identity_lockdown",
        "adjusted": False,
        "reason": "supported",
    }

    assert adjusted.status_code == 200
    assert adjusted.json()["provider"] == "active_directory"
    assert adjusted.json()["supported"] is False
    assert adjusted.json()["recommended_action"] == "degrade_privileges"
    assert adjusted.json()["adjusted"] is True

    assert missing.status_code == 404
