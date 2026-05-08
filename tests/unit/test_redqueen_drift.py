from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.settings import settings
from app.models.risk_score import RiskScore
from app.redqueen.drift import analyze_risk_drift


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def _add_score(db_session, *, target: str, score: float, minutes_ago: int):
    row = RiskScore(
        asset_id=target,
        score_0_100=score,
        confidence=0.8,
        factors="[]",
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        trend="stable",
    )
    db_session.add(row)
    db_session.commit()
    return row


def test_redqueen_drift_detects_risk_spike(db_session):
    target = "asset-drift-01"
    for idx, score in enumerate([35, 38, 34, 36, 37], start=1):
        _add_score(db_session, target=target, score=score, minutes_ago=idx)

    drift = analyze_risk_drift(db_session, target=target, current_score=82)

    assert drift["status"] == "ok"
    assert drift["severity"] in {"high", "critical"}
    assert drift["delta"] >= 40
    assert "drift:risk_spike" in drift["signals"]
    assert drift["recommended_controls"]["requires_human"] is True


@pytest.mark.asyncio
async def test_redqueen_drift_endpoint(test_client, db_session, monkeypatch):
    target = "asset-drift-api-01"
    for idx, score in enumerate([42, 43, 41], start=1):
        _add_score(db_session, target=target, score=score, minutes_ago=idx)

    resp = await test_client.get(
        f"/api/v1/redqueen/drift/{target}?current_score=79",
        headers=autonomy_headers(monkeypatch),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target"] == target
    assert body["severity"] in {"high", "critical"}
    assert "drift:risk_spike" in body["signals"]


@pytest.mark.asyncio
async def test_redqueen_verdict_records_risk_drift(test_client, db_session, monkeypatch):
    target = "asset-drift-verdict-01"
    for idx, score in enumerate([30, 32, 31, 33], start=1):
        _add_score(db_session, target=target, score=score, minutes_ago=idx)

    resp = await test_client.post(
        "/api/v1/redqueen/verdict",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": target,
            "risk_score": 88,
            "factors": ["identity_anomaly"],
            "execution_controls": {"dry_run": True},
        },
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "drift:risk_spike" in body["factors"]
    assert body["execution_controls"]["risk_drift"]["severity"] in {"high", "critical"}
