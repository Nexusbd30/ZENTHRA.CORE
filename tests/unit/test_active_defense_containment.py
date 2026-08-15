from app.ares.aggressive_containment import build_aggressive_containment
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
