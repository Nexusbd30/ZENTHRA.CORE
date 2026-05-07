import pytest

from app.core.settings import settings
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_lifecycle_persists_verdict_and_execution(test_client, db_session, monkeypatch):
    before_verdict = db_session.query(Verdict).count()
    before_results = db_session.query(ExecutionResult).count()

    resp = await test_client.post(
        "/api/v1/ares/lifecycle",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": "asset-persist-01",
            "risk_score": 78,
            "factors": ["suspicious_auth", "lateral_movement"],
            "execution_controls": {"change_ticket": "TEST-ARES-PERSIST-001"},
            "human_approved": True,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    after_verdict = db_session.query(Verdict).count()
    after_results = db_session.query(ExecutionResult).count()

    assert after_verdict == before_verdict + 1
    assert after_results == before_results + 1
    assert body["execution"]["status"] in {"executed", "failed"}


@pytest.mark.asyncio
async def test_transactional_rollback_on_simulated_failure(test_client, monkeypatch):
    resp = await test_client.post(
        "/api/v1/ares/lifecycle",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": "asset-rollback-01",
            "risk_score": 76,
            "factors": ["endpoint_compromise"],
            "execution_controls": {
                "simulate_failure_after_steps": 1,
                "change_ticket": "TEST-ARES-ROLLBACK-001",
            },
            "human_approved": True,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["execution"]["status"] == "failed"
    execution = body["execution"]["execution"]
    assert execution["status"] == "failed"
    assert len(execution.get("rollback_events", [])) >= 1
