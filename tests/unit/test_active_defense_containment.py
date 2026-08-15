from app.ares.aggressive_containment import build_aggressive_containment
from app.ares.enterprise_active_defense import build_enterprise_active_defense
from app.ares.planner import build_plan
from app.redqueen.bridge_trace import build_bridge_trace
from app.redqueen.decision_engine import generate_verdict
from app.redqueen.policy_matrix import evaluate_policy


def test_redqueen_bridge_trace_extracts_origin_and_blocks():
    trace = build_bridge_trace(
        target="prod-api",
        factors=["credential_attack", "lateral_movement", "devsecops_actor:svc-release"],
        controls={
            "perception": {
                "normalized_payload": {
                    "src_ip": "203.0.113.10",
                    "identity_context": {
                        "subject": {"upn": "admin@example.com"},
                        "session": {"session_id": "sess-123", "device_id": "laptop-7"},
                    },
                    "devsecops_context": {
                        "pipeline": {
                            "repository": "nexus/platform",
                            "pipeline_id": "deploy-prod",
                        }
                    },
                }
            }
        },
    )

    assert trace["schema"] == "vaelqorix.redqueen.bridge_trace.v1"
    assert trace["external_action_policy"] == "block_and_report_only"
    assert trace["origin_candidates"]
    assert {item["type"] for item in trace["block_targets"]} >= {
        "network_indicator",
        "identity",
        "session",
        "device",
        "repository",
        "pipeline",
    }
    assert "no_counter_intrusion" in trace["trace_boundaries"]


def test_verdict_carries_bridge_trace_for_ares(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"aggressive_containment","confidence":0.91,'
            '"reasoning":"active intrusion bridge observed","factors":["lateral_movement"]}'
        ),
    )

    verdict = generate_verdict(
        target="prod-api",
        risk_score=92,
        factors=["credential_attack", "lateral_movement"],
        execution_controls={
            "perception": {
                "normalized_payload": {
                    "src_ip": "198.51.100.20",
                    "identity_context": {"session": {"session_id": "sess-456"}},
                }
            }
        },
    )

    bridge_trace = verdict["execution_controls"]["redqueen_bridge_trace"]

    assert verdict["action_type"] == "aggressive_containment"
    assert bridge_trace["schema"] == "vaelqorix.redqueen.bridge_trace.v1"
    assert "bridge_block_targets:" + str(len(bridge_trace["block_targets"])) in verdict["factors"]
    assert verdict["requires_human"] is True
    assert verdict["signature"]


def test_ares_aggressive_containment_is_defensive_and_operator_gated():
    verdict = {
        "target": "prod-api",
        "action_type": "aggressive_containment",
        "risk_score": 88,
    }
    bridge_trace = {
        "block_targets": [
            {
                "type": "network_indicator",
                "value": "198.51.100.20",
                "action": "block_inbound_and_watch_egress",
            },
            {"type": "session", "value": "sess-456", "action": "revoke_or_lock"},
        ]
    }

    containment = build_aggressive_containment(
        verdict=verdict,
        bridge_trace=bridge_trace,
        controls={"change_ticket": "CHG-1"},
    )
    plan = build_plan(verdict)
    policy = evaluate_policy(score=88, action_type="aggressive_containment")

    assert containment["schema"] == "vaelqorix.ares.aggressive_containment.v1"
    assert containment["external_action_policy"] == "block_and_report_only"
    assert "no_external_counter_intrusion" in containment["guardrails"]
    assert {step["control"] for step in containment["neutralization_steps"]} >= {
        "perimeter_block",
        "identity_revocation",
        "open_traceability_case",
    }
    assert plan["requires_confirmation"] is True
    assert plan["rollback_strategy"] == "transactional_reverse_order"
    assert policy["allowed"] is True
    assert policy["requires_human"] is True


def test_enterprise_active_defense_builds_vendor_grade_controls():
    trace = build_bridge_trace(
        target="customer-portal",
        factors=[
            "credential_attack",
            "asn:AS64500",
            "geo_country:RU",
            "domain:callback.example.test",
        ],
        controls={
            "perception": {
                "normalized_payload": {
                    "src_ip": "198.51.100.42",
                    "identity_context": {
                        "subject": {"upn": "finance-admin@example.com"},
                        "session": {"session_id": "sess-fin-1", "device_id": "workstation-44"},
                    },
                    "devsecops_context": {
                        "pipeline": {
                            "repository": "nexus/customer-portal",
                            "pipeline_id": "release-prod",
                            "runner_id": "runner-prod-3",
                        }
                    },
                }
            }
        },
    )
    active_defense = build_enterprise_active_defense(
        verdict={
            "verdict_id": "v-1",
            "target": "customer-portal",
            "action_type": "aggressive_containment",
            "risk_score": 94,
        },
        bridge_trace=trace,
        controls={"case_id": "CASE-9000", "countermeasure_level": "aggressive_defensive"},
    )

    control_names = {item["name"] for item in active_defense["controls"]}
    assert trace["external_action_policy"] == "block_and_report_only"
    assert {"asn", "geo_country", "domain"} <= {item["type"] for item in trace["block_targets"]}
    assert control_names >= {
        "perimeter_auto_block",
        "identity_burn_protocol",
        "endpoint_workload_isolation",
        "devsecops_release_freeze",
        "waf_edr_siem_rule_deployment",
        "deception_grid",
        "authorized_sinkhole",
    }
    assert "legal_escalation_pack" in active_defense["execution_order"]
    assert active_defense["legal_escalation_pack"]["case_id"] == "CASE-9000"
    assert "no_hack_back" in active_defense["guardrails"]


def test_aggressive_containment_embeds_enterprise_active_defense():
    containment = build_aggressive_containment(
        verdict={
            "verdict_id": "v-2",
            "target": "api-gateway",
            "action_type": "aggressive_containment",
            "risk_score": 90,
        },
        bridge_trace={
            "target": "api-gateway",
            "block_targets": [
                {"type": "asn", "value": "AS64500", "action": "rate_limit_or_block_asn"},
                {
                    "type": "domain",
                    "value": "callback.example.test",
                    "action": "dns_block_or_authorized_sinkhole",
                },
            ],
            "origin_candidates": [],
            "pivot_chain": [],
            "evidence_sources": ["threat_perception"],
        },
        controls={"change_ticket": "CHG-900"},
    )

    enterprise = containment["enterprise_active_defense"]
    assert containment["external_action_policy"] == "block_and_report_only"
    assert enterprise["schema"] == "vaelqorix.ares.enterprise_active_defense.v1"
    assert enterprise["external_action_policy"] == "block_report_preserve_only"
    assert "authorized_sinkhole" in {item["name"] for item in enterprise["controls"]}
    assert "no_external_counter_intrusion" in containment["guardrails"]
