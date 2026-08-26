from datetime import UTC, datetime, timedelta

from app.ares.reporter import build_execution_result
from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
from app.redqueen.decision_engine import ACTION_SEVERITY, generate_verdict
from app.redqueen.perception import build_threat_perception
from app.redqueen.prompts import tactical_user_prompt
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
    assert verdict["execution_controls"]["redqueen_thinking_model"]["primary_goal"] == (
        "control_intrusion_and_block_threats"
    )
    assert verdict["execution_controls"]["redqueen_thinking_model"]["execution_boundary"] == (
        "redqueen_decides_ares_executes"
    )
    assert verdict["execution_controls"]["redqueen_thinking_model"]["redqueen_control_percent"] == 80
    assert verdict["execution_controls"]["redqueen_thinking_model"]["human_control_percent"] == 20
    assert "execution_boundary:ares_only" in verdict["factors"]
    assert "analytical_posture:critical_review" in verdict["factors"]
    assert verdict["execution_controls"]["redqueen_analytical_profile"]["schema"] == (
        "vaelqorix.redqueen.analytical_brain.v1"
    )
    assert verdict["execution_controls"]["redqueen_analytical_profile"]["diligence_score"] >= 80
    assert verdict["execution_controls"]["policy_result"]["code"] == "human_required"
    assert verdict["causal_chain"]["action"] == "network_isolate"


def test_redqueen_prompt_prioritizes_intrusion_control_and_ares_execution():
    prompt = tactical_user_prompt(
        target="edge-fw-01",
        risk_score=91,
        factors=["lateral_movement", "active_exfiltration"],
    )

    assert "control defensivo" in prompt
    assert "bloqueo de amenaza" in prompt
    assert "ARES" in prompt
    assert "RedQueen 80%" in prompt
    assert "ser humano 20%" in prompt
    assert "no ejecuta acciones operativas" in prompt


def test_redqueen_requires_human_at_80_percent_boundary(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"soar_delegate","confidence":0.80,'
            '"reasoning":"delegate controlled response","factors":["controlled_response"]}'
        ),
    )

    verdict = generate_verdict(
        target="srv-auth",
        risk_score=80,
        factors=["credential_attack"],
        execution_controls={},
    )

    assert verdict["requires_human"] is True
    assert verdict["execution_controls"]["redqueen_thinking_model"]["autonomy_threshold"] == 80


def test_verdict_records_mcp_action_policy_when_action_is_blocked(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"network_isolate","confidence":0.92,'
            '"reasoning":"contain critical host","factors":["llm_containment"]}'
        ),
    )

    verdict = generate_verdict(
        target="critical-db",
        risk_score=97,
        factors=["data_exfiltration"],
        execution_controls={"mcp_context": {"blocked_actions": ["network_isolate"]}},
    )

    assert verdict["action_type"] == "network_isolate"
    assert verdict["execution_controls"]["mcp_action_policy"]["allowed"] is False
    assert verdict["execution_controls"]["mcp_action_policy"]["code"] == "mcp_action_blocked"


def test_redqueen_can_authorize_dns_firewall_block_for_network_domain(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"dns_firewall_block","confidence":0.91,'
            '"reasoning":"block command and control domain",'
            '"factors":["dns_callback","command_and_control"]}'
        ),
    )

    verdict = generate_verdict(
        target="malware.example",
        risk_score=72,
        factors=["dns_callback"],
        execution_controls={
            "perception": {
                "entity_type": "network",
                "source": "network_sensor:dns",
            },
        },
    )

    assert verdict["action_type"] == "dns_firewall_block"
    assert verdict["execution_controls"]["action_domain"] == "network"
    assert verdict["execution_controls"]["llm_governance"]["approved_for_ares"] is True
    assert verdict["causal_chain"]["action"] == "dns_firewall_block"


def test_verdict_records_mcp_tool_policy_for_declared_tools(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"soar_delegate","confidence":0.70,'
            '"reasoning":"delegate with evidence","factors":["mcp_supported"]}'
        ),
    )

    verdict = generate_verdict(
        target="release-prod",
        risk_score=55,
        factors=["pipeline_risk"],
        execution_controls={
            "mcp_context": {
                "tools": ["identity.lookup", "pipeline.lookup"],
                "allowed_tools": ["identity.lookup", "pipeline.lookup"],
            }
        },
    )

    assert verdict["execution_controls"]["mcp_tool_policy"]["schema"] == (
        "vaelqorix.mcp_tool_policy.v1"
    )
    assert verdict["execution_controls"]["mcp_tool_policy"]["allowed"] is True
    assert verdict["execution_controls"]["mcp_tool_policy"]["requested_tools"] == [
        "identity.lookup",
        "pipeline.lookup",
    ]


def test_redqueen_adjusts_devsecops_action_to_provider_capability(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"block_deployment","confidence":0.94,'
            '"reasoning":"block risky release","factors":["critical_pipeline_risk"]}'
        ),
    )

    verdict = generate_verdict(
        target="repository:vaelqorix/core-security",
        risk_score=95,
        factors=["secret_exposure"],
        execution_controls={
            "devsecops_contract": "devsecops_signal.v1",
            "devsecops_provider": "sonarqube",
            "perception": {
                "entity_type": "repository",
                "source": "devsecops:sonarqube",
            },
        },
    )

    assert verdict["action_type"] == "require_release_approval"
    assert verdict["execution_controls"]["provider_action_adjusted"] is True
    assert verdict["execution_controls"]["provider_original_action_type"] == "block_deployment"
    assert verdict["execution_controls"]["provider_adjustment_reason"] == (
        "devsecops_provider_capability_adjustment:sonarqube"
    )
    assert "provider_adjusted_to:require_release_approval" in verdict["factors"]
    result = build_execution_result(
        verdict=verdict,
        execution={"status": "success", "duration_ms": 0, "executed_steps": []},
    )
    trace = [item for item in result["evidence"] if item.get("kind") == "intelligence_trace"][0]
    assert trace["provider_action_adjusted"] is True
    assert trace["provider_adjustment_reason"] == (
        "devsecops_provider_capability_adjustment:sonarqube"
    )


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


def test_perception_and_risk_scorer_use_ueba_behavior_signals():
    threat = ThreatModel(
        title="Impossible travel and password spray against privileged account",
        source="wazuh",
        description="Multiple failed logins from many countries during off-hours.",
        level=ThreatLevel.medium,
        category=ThreatCategory.auth,
        score=None,
        target_service="admin-portal",
        source_ip="203.0.113.10",
        siem_metadata={
            "status": "open",
            "occurrences": 4,
            "behavior": {
                "failed_logins": 24,
                "distinct_source_ips": 9,
                "geo_velocity_kmh": 1400,
                "new_country": True,
                "off_hours": True,
                "privileged_account": True,
            },
            "evidence": {
                "labels": {
                    "alertname": "IdentityBehaviorAnomaly",
                    "severity": "high",
                    "instance": "admin-portal",
                },
                "annotations": {
                    "summary": "Impossible travel detected after password spray",
                },
            },
        },
    )
    threat.id = "threat-ueba-001"

    perception = build_threat_perception(threat)
    risk = score_perception(perception)

    assert perception["ueba"]["anomaly_score"] >= 80
    assert "ueba:credential_attack" in perception["ueba"]["signals"]
    assert "ueba:impossible_travel" in perception["factors"]
    assert "ueba:privileged_account" in risk["score_inputs"]["ueba_signals"]
    assert risk["score_inputs"]["ueba_anomaly_score"] >= 80
    assert risk["risk_score"] >= 85
