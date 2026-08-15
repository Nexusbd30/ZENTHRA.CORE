from app.ares.os_business_shield import build_os_business_shield
from app.redqueen.anticipation import anticipate_attack_path
from app.redqueen.decision_engine import generate_verdict


def test_redqueen_anticipates_attack_path_for_business_infrastructure():
    anticipation = anticipate_attack_path(
        target="identity-core",
        risk_score=88,
        factors=[
            "credential_attack",
            "identity_mfa:absent",
            "privilege_escalation",
            "lateral_movement",
        ],
        controls={
            "mcp_context": {
                "critical_dependency": True,
                "asset_tier": "crown_jewel",
                "blast_radius": "enterprise",
            }
        },
    )

    assert anticipation["schema"] == "vaelqorix.redqueen.attack_anticipation.v1"
    assert anticipation["horizon"] in {"near_term", "immediate"}
    assert "initial_access" in anticipation["attack_stages"]
    assert "lateral_movement" in anticipation["attack_stages"]
    assert "require_mfa" in anticipation["preventive_controls"]
    assert "segment_network" in anticipation["preventive_controls"]
    assert "critical_dependency_in_blast_radius" in anticipation["early_warnings"]


def test_verdict_carries_signed_attack_anticipation(monkeypatch):
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"system_harden","confidence":0.86,'
            '"reasoning":"preemptive hardening","factors":["credential_attack"]}'
        ),
    )

    verdict = generate_verdict(
        target="identity-core",
        risk_score=62,
        factors=["credential_attack", "identity_mfa:absent"],
        execution_controls={"mcp_context": {"critical_dependency": True}},
    )

    anticipation = verdict["execution_controls"]["redqueen_attack_anticipation"]

    assert verdict["action_type"] == "system_harden"
    assert anticipation["schema"] == "vaelqorix.redqueen.attack_anticipation.v1"
    assert "attack_horizon:" + anticipation["horizon"] in verdict["factors"]
    assert "require_mfa" in anticipation["preventive_controls"]
    assert verdict["signature"]


def test_ares_builds_os_business_shield_from_anticipation():
    anticipation = {
        "horizon": "near_term",
        "latest_stage": "lateral_movement",
        "attack_stages": ["initial_access", "privilege_escalation", "lateral_movement"],
        "preventive_controls": [
            "require_mfa",
            "review_admin_groups",
            "segment_network",
            "tighten_east_west_rules",
        ],
    }

    shield = build_os_business_shield(
        target="identity-core",
        action_type="system_harden",
        anticipation=anticipation,
        controls={
            "dependency_owner_approved": True,
            "firewall_policy": {"protected_targets": ["identity-core"]},
        },
    )

    assert shield["schema"] == "vaelqorix.ares.os_business_shield.v1"
    assert shield["mode"] == "preventive_defense"
    assert {layer["layer"] for layer in shield["shield_layers"]} >= {"identity", "network"}
    assert "dependency_owner_approved" in shield["guardrails"]
    assert shield["protected_targets"] == ["identity-core"]
