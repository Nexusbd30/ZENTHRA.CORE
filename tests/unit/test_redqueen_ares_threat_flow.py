import uuid

import pytest

from app.core.settings import settings


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


async def create_admin_threat(test_client, auth_token, *, score=73):
    payload = {
        "title": f"Suspicious auth burst {uuid.uuid4().hex[:6]}",
        "source": "prometheus/correlation",
        "description": "Multiple failed auth attempts followed by privileged access.",
        "level": "high",
        "category": "auth",
        "score": score,
        "target_service": "identity-api",
        "source_ip": "10.10.20.30",
    }
    resp = await test_client.post(
        "/threats/",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_redqueen_issues_verdict_from_existing_threat(test_client, auth_token, monkeypatch):
    threat = await create_admin_threat(test_client, auth_token, score=74)

    resp = await test_client.post(
        f"/api/v1/redqueen/verdict/from-threat/{threat['id']}",
        headers=autonomy_headers(monkeypatch),
        json={},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["threat_id"] == threat["id"]
    assert body["perception"]["target"] == "identity-api"
    assert body["risk"]["risk_score"] >= 74
    assert body["verdict"]["target"] == "identity-api"
    assert body["verdict"]["signature"]


@pytest.mark.asyncio
async def test_ares_lifecycle_from_existing_threat_executes(test_client, auth_token, monkeypatch):
    threat = await create_admin_threat(test_client, auth_token, score=77)

    resp = await test_client.post(
        f"/api/v1/ares/lifecycle/from-threat/{threat['id']}",
        headers=autonomy_headers(monkeypatch),
        json={"human_approved": True},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["verdict"]["execution_controls"]["threat_id"] == threat["id"]
    assert body["execution"]["status"] in {"executed", "failed"}
    assert body["execution"]["result"]["verdict_id"] == body["verdict"]["verdict_id"]


@pytest.mark.asyncio
async def test_ares_lifecycle_from_threat_supports_dry_run(test_client, auth_token, monkeypatch):
    threat = await create_admin_threat(test_client, auth_token, score=84)

    resp = await test_client.post(
        f"/api/v1/ares/lifecycle/from-threat/{threat['id']}",
        headers=autonomy_headers(monkeypatch),
        json={
            "human_approved": True,
            "execution_controls": {"dry_run": True},
        },
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    execution = body["execution"]["execution"]
    assert body["execution"]["status"] == "executed"
    assert execution["mode"] == "dry_run"
    assert execution["advisor_review"]["provider"] == "llm"
    assert execution["rollback_available"] is False
    assert all(step["status"] == "planned" for step in execution["executed_steps"])
