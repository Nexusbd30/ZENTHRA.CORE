from __future__ import annotations

import pytest

from app.core.settings import settings
from app.db.audit_store import append_audit_record


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_secops_readiness_endpoints_are_granular_and_sanitized(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "ghp-test")
    monkeypatch.setattr(settings, "GITHUB_API_BASE_URL", "https://api.github.com")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_URL", "https://soc.example/webhook")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_TOKEN", "soc-token")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_HMAC_SECRET", "soc-secret")

    github = await test_client.get(
        "/api/v1/secops/providers/github_actions/readiness",
        headers=headers,
    )
    redis = await test_client.get("/api/v1/secops/readiness/redis", headers=headers)
    soc = await test_client.get("/api/v1/secops/readiness/soc-webhook", headers=headers)
    secrets = await test_client.get("/api/v1/secops/readiness/secrets", headers=headers)
    ingestion = await test_client.get("/api/v1/secops/readiness/ingestion", headers=headers)
    all_checks = await test_client.get("/api/v1/secops/integrations/readiness", headers=headers)

    assert github.status_code == 200
    assert github.json()["status"] == "ready"
    assert github.json()["token_configured"] is True
    assert github.json()["secrets_exposed"] is False
    assert "ghp-test" not in github.text

    assert redis.status_code == 200
    assert redis.json()["integration"] == "redis"
    assert redis.json()["secrets_exposed"] is False

    assert soc.status_code == 200
    assert soc.json()["status"] == "ready"
    assert "soc-secret" not in soc.text
    assert "soc-token" not in soc.text

    assert secrets.status_code == 200
    assert secrets.json()["integration"] == "secret_backend"
    assert secrets.json()["secrets_exposed"] is False

    assert ingestion.status_code == 200
    assert ingestion.json()["sentinel"]["configured"] is True
    assert ingestion.json()["wazuh"]["configured"] is True

    assert all_checks.status_code == 200
    assert "github_actions" in all_checks.json()["checks"]


@pytest.mark.asyncio
async def test_secops_execution_preflight_blocks_real_mode_without_change_ticket(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "ghp-test")
    monkeypatch.setattr(settings, "GITHUB_API_BASE_URL", "https://api.github.com")

    blocked = await test_client.post(
        "/api/v1/secops/execution/preflight",
        headers=headers,
        json={
            "provider": "github_actions",
            "action_type": "block_deployment",
            "execution_controls": {"dry_run": False},
        },
    )
    allowed = await test_client.post(
        "/api/v1/secops/execution/preflight",
        headers=headers,
        json={
            "provider": "github_actions",
            "action_type": "block_deployment",
            "execution_controls": {"dry_run": False, "change_ticket": "CHG-SECOPS-1"},
        },
    )

    assert blocked.status_code == 200
    assert blocked.json()["allowed"] is False
    assert blocked.json()["checks"]["real_mode_change_ticket_required"] is False
    assert allowed.status_code == 200
    assert allowed.json()["allowed"] is True
    assert allowed.json()["mode"] == "real"


@pytest.mark.asyncio
async def test_phase2_controlled_e2e_sentinel_to_ares_and_soc_export(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    monkeypatch.setattr(settings, "SOC_WEBHOOK_URL", "https://soc.example/webhook")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_TOKEN", "soc-token")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_HMAC_SECRET", "soc-secret")

    calls = []

    class FakeResponse:
        status_code = 202
        text = "accepted"
        headers = {"x-request-id": "soc-req-1"}

        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("app.secops.service.requests.post", fake_post)

    ingest = await test_client.post(
        "/api/v1/ingestion/events/sentinel",
        headers=headers,
        json={
            "incidentNumber": "9001",
            "title": "Critical release pipeline compromise",
            "severity": "Critical",
            "compromisedEntity": "release-prod",
            "sourceIp": "203.0.113.50",
            "description": "Privileged token theft in release workflow",
        },
    )
    assert ingest.status_code == 200
    threat_id = ingest.json()["threat_id"]

    verdict = await test_client.post(
        f"/api/v1/redqueen/verdict/from-threat/{threat_id}",
        headers=headers,
        json={"execution_controls": {"dry_run": True}},
    )
    assert verdict.status_code == 200
    assert verdict.json()["status"] == "ok"
    assert verdict.json()["verdict"]["requires_human"] is True

    dry_run = await test_client.post(
        f"/api/v1/ares/lifecycle/from-threat/{threat_id}",
        headers=headers,
        json={
            "execution_controls": {
                "dry_run": True,
                "change_ticket": "CHG-E2E-DRYRUN",
            },
            "human_approved": True,
        },
    )
    assert dry_run.status_code == 200
    assert dry_run.json()["execution"]["execution"]["mode"] == "dry_run"

    real_without_approval = await test_client.post(
        f"/api/v1/ares/lifecycle/from-threat/{threat_id}",
        headers=headers,
        json={
            "execution_controls": {
                "dry_run": False,
                "change_ticket": "CHG-E2E-REAL",
            },
            "human_approved": False,
        },
    )
    assert real_without_approval.status_code == 200
    assert real_without_approval.json()["execution"]["status"] == "pending_human_approval"

    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="identity-webhook",
        action="identity_entra_webhook_rejected",
        result={
            "reason": "invalid_signature",
            "status_code": 403,
            "provider": "entra",
            "source": "entra",
            "source_event_id": "entra-e2e-1",
            "tenant_id": "tenant-e2e",
            "capability": "identity:ingest",
            "client_ip": "203.0.113.9",
            "payload_sha256": "abc123",
            "secrets_exposed": False,
        },
    )

    export = await test_client.post(
        "/api/v1/secops/security/events/export",
        headers=headers,
        json={
            "destination": "generic_webhook",
            "format": "soc_case.v1",
            "send": True,
            "limit": 10,
        },
    )
    assert export.status_code == 200
    assert export.json()["delivery"]["status"] == "sent"
    assert calls[0][0] == "https://soc.example/webhook"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer soc-token"

    audit = await test_client.get("/api/v1/ares/audit/verify", headers=headers)
    assert audit.status_code == 200
    assert audit.json()["valid"] is True
