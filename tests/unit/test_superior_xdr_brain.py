from app.ares.enterprise_active_defense import build_enterprise_active_defense
from app.ares.response_fabric import build_response_fabric
from app.redqueen.bridge_trace import build_bridge_trace
from app.redqueen.decision_engine import generate_verdict
from app.redqueen.strategic_anticipation import build_strategic_anticipation
from app.sensors.network_sensor import collect_network_findings


def test_redqueen_strategic_anticipation_uses_native_telemetry_and_bridge_trace():
    finding = collect_network_findings(
        {
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.9",
            "dst_port": 4444,
            "connection_count": 5,
            "unique_hosts": 15,
            "east_west": True,
            "dns_query": "callback.example.test",
        }
    )[0]
    event = finding.to_aresx_event()
    event["signals"] = finding.signals
    bridge_trace = build_bridge_trace(
        target="payments-api",
        factors=["credential_attack", "lateral_movement", "domain:callback.example.test"],
        controls={"sensor_events": [event], "origin_candidates": [{"type": "ip", "value": "198.51.100.9"}]},
    )
    strategic = build_strategic_anticipation(
        target="payments-api",
        risk_score=93,
        factors=["credential_attack", "lateral_movement"],
        anticipation={
            "confidence": 0.82,
            "horizon": "near_term",
            "attack_stages": ["initial_access", "lateral_movement"],
        },
        bridge_trace=bridge_trace,
        controls={
            "sensor_events": [event],
            "mcp_context": {"asset_tier": "crown_jewel", "blast_radius": "enterprise"},
        },
    )

    assert strategic["schema"] == "vaelqorix.redqueen.strategic_anticipation.v1"
    assert strategic["stage_velocity"] == "breakout_imminent"
    assert strategic["intervention_window"] == "0-15m"
    assert strategic["business_priority"] == "protect_crown_jewels"
    assert strategic["decision_advantage"]["uses_native_telemetry"] is True
    assert strategic["decision_advantage"]["uses_bridge_trace"] is True
    assert {item["provider_family"] for item in strategic["next_best_actions"]} >= {
        "firewall_waf_ndr",
        "iam_idp",
        "edr_kubernetes_cloud",
    }


def test_verdict_embeds_strategic_anticipation(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"aggressive_containment","confidence":0.91,'
            '"reasoning":"fast moving intrusion","factors":["lateral_movement"]}'
        ),
    )

    verdict = generate_verdict(
        target="payments-api",
        risk_score=94,
        factors=["credential_attack", "lateral_movement"],
        execution_controls={
            "mcp_context": {"asset_tier": "crown_jewel"},
            "origin_candidates": [{"type": "ip", "value": "198.51.100.9"}],
        },
    )

    strategic = verdict["execution_controls"]["redqueen_strategic_anticipation"]

    assert strategic["business_priority"] == "protect_crown_jewels"
    assert "strategic_velocity:" + strategic["stage_velocity"] in verdict["factors"]
    assert "intervention_window:" + strategic["intervention_window"] in verdict["factors"]
    assert verdict["signature"]


def test_ares_response_fabric_routes_next_best_actions_to_ready_connectors():
    bridge_trace = {
        "target": "payments-api",
        "block_targets": [
            {"type": "network_indicator", "value": "198.51.100.9"},
            {"type": "domain", "value": "callback.example.test"},
            {"type": "session", "value": "sess-1"},
        ],
        "origin_candidates": [],
        "pivot_chain": [],
        "evidence_sources": ["native_network_sensor"],
    }
    verdict = {
        "verdict_id": "v-superior",
        "target": "payments-api",
        "risk_score": 95,
        "requires_human": True,
        "execution_controls": {"tenant_id": "tenant-enterprise"},
    }
    enterprise = build_enterprise_active_defense(verdict=verdict, bridge_trace=bridge_trace)
    strategic = {
        "target": "payments-api",
        "business_priority": "protect_crown_jewels",
        "next_best_actions": [
            {
                "action": "block_observed_indicators",
                "provider_family": "firewall_waf_ndr",
                "urgency": "immediate",
                "reason": "bridge_trace_has_block_targets",
            },
            {
                "action": "preserve_evidence",
                "provider_family": "case",
                "urgency": "immediate",
                "reason": "maintain_chain_of_custody",
            },
        ],
    }

    fabric = build_response_fabric(
        verdict=verdict,
        strategic_anticipation=strategic,
        enterprise_active_defense=enterprise,
        controls={
            "configured_connector_secrets": {
                "paloalto": {"PALOALTO_API_KEY": "set", "PALOALTO_BASE_URL": "set"},
                "jira": {"JIRA_EMAIL": "set", "JIRA_API_TOKEN": "set", "JIRA_BASE_URL": "set"},
            }
        },
    )

    selected = {route["provider_family"]: route["selected_provider"] for route in fabric["routes"]}
    assert fabric["schema"] == "vaelqorix.ares.response_fabric.v1"
    assert fabric["tenant_id"] == "tenant-enterprise"
    assert fabric["blast_radius"] == "enterprise"
    assert selected["firewall_waf_ndr"] == "paloalto"
    assert selected["case"] == "jira"
    assert "no_hack_back" in fabric["safety_boundary"]
