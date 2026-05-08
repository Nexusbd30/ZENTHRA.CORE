from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.settings import settings
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict
from app.redqueen.trainer import build_training_report


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def _add_feedback(
    db_session,
    *,
    verdict_id: str,
    action_type: str,
    status: str,
    confidence: float = 0.9,
    factors: str = '["ueba:privileged_account"]',
    minutes_ago: int = 1,
):
    db_session.add(
        Verdict(
            verdict_id=verdict_id,
            timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
            target=f"asset-{verdict_id}",
            action_type=action_type,
            risk_score=90,
            confidence=confidence,
            factors=factors,
            justification_xai="test",
            policy_check=True,
            requires_human=True,
            execution_controls="{}",
            signature="sig",
        )
    )
    db_session.add(
        ExecutionResult(
            verdict_id=verdict_id,
            ares_id="ares",
            status=status,
            duration_ms=10,
            evidence="[]",
            error_code="" if status == "success" else "execution_failed",
            result_hash=f"hash-{verdict_id}",
            timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        )
    )
    db_session.commit()


def test_redqueen_trainer_builds_feedback_report(db_session):
    _add_feedback(
        db_session,
        verdict_id="trainer-1",
        action_type="trainer_network_isolate",
        status="failed",
    )
    _add_feedback(
        db_session,
        verdict_id="trainer-2",
        action_type="trainer_network_isolate",
        status="failed",
    )
    _add_feedback(
        db_session,
        verdict_id="trainer-3",
        action_type="soar_delegate",
        status="success",
        confidence=0.7,
    )

    report = build_training_report(db_session)

    assert report["status"] == "ok"
    assert report["sample_count"] >= 3
    assert report["action_performance"]["trainer_network_isolate"]["success_rate"] == 0.0
    assert "review_action_policy:trainer_network_isolate" in report["recommendations"]
    assert "ueba:privileged_account" in {
        item["factor"] for item in report["failure_factors"]
    }


@pytest.mark.asyncio
async def test_redqueen_training_report_endpoint(test_client, db_session, monkeypatch):
    _add_feedback(
        db_session,
        verdict_id="trainer-api-1",
        action_type="trainer_endpoint_isolate",
        status="failed",
    )
    _add_feedback(
        db_session,
        verdict_id="trainer-api-2",
        action_type="trainer_endpoint_isolate",
        status="failed",
    )

    resp = await test_client.get(
        "/api/v1/redqueen/training/report",
        headers=autonomy_headers(monkeypatch),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert "trainer_endpoint_isolate" in body["action_performance"]
    assert "review_action_policy:trainer_endpoint_isolate" in body["recommendations"]
