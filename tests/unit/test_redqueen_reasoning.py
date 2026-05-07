from datetime import UTC, datetime, timedelta

from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
from app.redqueen.decision_engine import ACTION_SEVERITY, generate_verdict
from app.redqueen.perception import build_threat_perception
from app.redqueen.risk_scorer import score_perception


def test_llm_cannot_downgrade_critical_action(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"observe","confidence":0.99,'
            '"reasoning":"try downgrade","factors":["llm_lowball"]}'
        ),
    )

    verdict = generate_verdict(
        target="critical-db",
        risk_score=97,
        factors=["data_exfiltration"],
        execution_controls={},
    )

    assert verdict["action_type"] == "network_isolate"
    assert ACTION_SEVERITY[verdict["action_type"]] >= ACTION_SEVERITY["network_isolate"]
    assert verdict["execution_controls"]["minimum_action_enforced"] is True
    assert verdict["causal_chain"]["action"] == "network_isolate"


def test_perception_and_risk_scorer_use_enriched_siem_signals():
    now = datetime.now(UTC)
    threat = ThreatModel(
        title="Potential data_exfiltration from database",
        source="prometheus/correlation",
        description="Large outbound transfer with privilege_escalation indicators.",
        level=ThreatLevel.high,
        category=ThreatCategory.database,
        score=None,
        target_service="db-api",
        source_ip="10.1.2.3",
        database_name="customer-data",
        database_host="db-prod-01",
        siem_metadata={
            "status": "open",
            "occurrences": 5,
            "first_seen_at": (now - timedelta(minutes=80)).isoformat(),
            "last_seen_at": now.isoformat(),
            "evidence": {
                "state": "firing",
                "value": "1",
                "labels": {
                    "alertname": "DatabaseExfiltration",
                    "job": "postgres-exporter",
                    "severity": "critical",
                    "instance": "db-prod-01",
                },
                "annotations": {
                    "summary": "Database exfiltration suspected",
                    "description": "Outbound transfer spike",
                },
            },
        },
    )
    threat.id = "threat-001"

    perception = build_threat_perception(threat)
    perception["mcp_context"] = {
        "critical_dependency": True,
        "asset_tier": "crown_jewel",
        "business_criticality": "critical",
        "blast_radius": "enterprise",
        "active_incident_count": 2,
    }
    risk = score_perception(perception)

    assert perception["target"] == "db-api"
    assert perception["siem"]["alertname"] == "DatabaseExfiltration"
    assert perception["siem"]["active_minutes"] >= 79
    assert "siem_severity:critical" in perception["factors"]
    assert "data_exfiltration" in risk["score_inputs"]["matched_signals"]
    assert "mcp:critical_dependency" in risk["score_inputs"]["mcp_factors"]
    assert "mcp:asset_tier:crown_jewel" in risk["score_inputs"]["mcp_factors"]
    assert risk["risk_score"] >= 90
