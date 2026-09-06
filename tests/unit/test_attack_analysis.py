from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.core.settings import settings
from app.models.threat_event import ThreatEvent


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def add_event(
    db_session,
    *,
    event_id: str,
    entity_id: str,
    event_type: str,
    severity: int,
    stage: str,
    mitre_tags: list[str],
    minutes: int,
    risk_score: float = 0.0,
    source: str = "identity:entra",
):
    event = ThreatEvent(
        source=source,
        event_id=event_id,
        occurred_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=minutes),
        event_type=event_type,
        severity=severity,
        entity_id=entity_id,
        entity_type="user",
        mitre_tags=json.dumps(mitre_tags),
        normalized_payload=json.dumps(
            {
                "kill_chain_stage": stage,
                "signals": ["privileged_identity", "mfa_absent"],
                "summary": f"{event_type} observed in {stage}",
            }
        ),
        risk_score=risk_score,
        src_ip="203.0.113.10",
    )
    db_session.add(event)
    db_session.commit()
    return event


@pytest.mark.asyncio
async def test_attack_analysis_classifies_correlated_attack(test_client, db_session, monkeypatch):
    headers = monitor_headers(monkeypatch)
    entity_id = "user:admin@corp.com"
    add_event(
        db_session,
        event_id="attack-1",
        entity_id=entity_id,
        event_type="impossible_travel_login",
        severity=8,
        stage="initial_access",
        mitre_tags=["T1078"],
        minutes=0,
        risk_score=75,
    )
    add_event(
        db_session,
        event_id="attack-2",
        entity_id=entity_id,
        event_type="credential_dumping",
        severity=9,
        stage="credential_access",
        mitre_tags=["T1003"],
        minutes=2,
        risk_score=88,
    )

    response = await test_client.get(
        f"/api/v1/attack-analysis/entities/{entity_id}",
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "attack_analysis"
    assert body["classification"] in {"confirmed_attack", "probable_attack"}
    assert body["attack_reality_score"] >= 70
    assert body["event_count"] == 2
    assert "kill_chain_stage:credential_access" in body["evidence"]
    assert "high_confidence_mitre:T1003" in body["evidence"]
    assert body["causal_chain"]["target"] == entity_id
    assert body["causal_chain"]["action"] in {"soar_delegate", "aggressive_containment"}
    assert body["attack_anticipation"]["schema"] == "vaelqorix.redqueen.attack_anticipation.v1"


@pytest.mark.asyncio
async def test_attack_analysis_marks_low_signal_as_false_positive_likely(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    entity_id = "host:dev-workstation"
    event = ThreatEvent(
        source="edr:defender",
        event_id="benign-1",
        occurred_at=datetime.now(UTC).replace(tzinfo=None),
        event_type="policy_info",
        severity=2,
        entity_id=entity_id,
        entity_type="host",
        mitre_tags="[]",
        normalized_payload=json.dumps({"summary": "Low severity policy event"}),
        risk_score=10,
    )
    db_session.add(event)
    db_session.commit()

    response = await test_client.get(
        f"/api/v1/attack-analysis/entities/{entity_id}",
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "false_positive_likely"
    assert "single_event_no_corroboration" in body["false_positive_signals"]
    assert "low_severity_low_risk" in body["false_positive_signals"]
    assert body["recommended_action"] == "observe"


@pytest.mark.asyncio
async def test_attack_analysis_can_issue_redqueen_verdict_from_analysis(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    entity_id = "user:release-admin@corp.com"
    add_event(
        db_session,
        event_id="verdict-analysis-1",
        entity_id=entity_id,
        event_type="token_reuse",
        severity=8,
        stage="initial_access",
        mitre_tags=["T1078", "T1110"],
        minutes=0,
        risk_score=80,
    )
    add_event(
        db_session,
        event_id="verdict-analysis-2",
        entity_id=entity_id,
        event_type="suspicious_command",
        severity=8,
        stage="execution",
        mitre_tags=["T1059"],
        minutes=1,
        risk_score=82,
    )

    response = await test_client.post(
        f"/api/v1/attack-analysis/entities/{entity_id}/verdict",
        headers=headers,
        json={"execution_controls": {"dry_run": True, "change_ticket": "TEST-ATTACK-001"}},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["analysis"]["attack_reality_score"] >= 70
    assert body["verdict"]["target"] == entity_id
    assert "attack_classification:probable_attack" in body["verdict"]["factors"]
    assert body["verdict"]["execution_controls"]["attack_analysis"]["entity_id"] == entity_id
    assert body["verdict"]["execution_controls"]["dry_run"] is True
