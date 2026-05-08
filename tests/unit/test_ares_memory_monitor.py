from __future__ import annotations

from datetime import datetime

import pytest

from app.ares.memory import read_ares_memory
from app.ares.monitor import evaluate_ares_health
from app.core.settings import settings
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def _persist_execution(db_session, *, target: str, verdict_id: str, status: str):
    verdict = Verdict(
        verdict_id=verdict_id,
        timestamp=datetime.utcnow(),
        target=target,
        action_type="network_isolate",
        risk_score=88,
        confidence=0.92,
        factors="[]",
        justification_xai="test",
        policy_check=True,
        requires_human=True,
        execution_controls="{}",
        signature="sig",
    )
    db_session.add(verdict)
    db_session.add(
        ExecutionResult(
            verdict_id=verdict_id,
            ares_id="ares",
            status=status,
            duration_ms=10,
            evidence="[]",
            error_code="" if status == "success" else "execution_failed",
            result_hash=f"hash-{verdict_id}",
            timestamp=datetime.utcnow(),
        )
    )
    db_session.commit()


def test_ares_memory_tracks_target_failures(db_session):
    target = "asset-memory-01"
    _persist_execution(db_session, target=target, verdict_id="memory-verdict-1", status="failed")
    _persist_execution(db_session, target=target, verdict_id="memory-verdict-2", status="failed")

    memory = read_ares_memory(db_session, target=target)
    health = evaluate_ares_health(memory)

    assert memory["count"] == 2
    assert memory["status_counts"]["failed"] == 2
    assert memory["action_counts"]["network_isolate"] == 2
    assert memory["consecutive_failures"] == 2
    assert health["status"] == "critical"
    assert "network_isolate" in health["recommended_controls"]["mcp_context"]["blocked_actions"]


@pytest.mark.asyncio
async def test_ares_monitor_endpoint_returns_recommended_controls(
    test_client,
    db_session,
    monkeypatch,
):
    target = "asset-monitor-01"
    _persist_execution(db_session, target=target, verdict_id="monitor-verdict-1", status="failed")
    _persist_execution(db_session, target=target, verdict_id="monitor-verdict-2", status="failed")

    resp = await test_client.get(
        f"/api/v1/ares/monitor/{target}",
        headers=autonomy_headers(monkeypatch),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["memory"]["count"] == 2
    assert body["health"]["status"] == "critical"
    assert body["health"]["recommended_controls"]["dry_run"] is True
