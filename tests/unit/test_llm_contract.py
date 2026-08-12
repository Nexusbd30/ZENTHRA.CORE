from __future__ import annotations

from app.intelligence.governance import assess_llm_contract
from app.intelligence.llm_contract import normalize_llm_decision


def test_llm_contract_normalizes_action_outside_domain_to_minimum_action():
    result = normalize_llm_decision(
        {
            "action_type": "network_isolate",
            "confidence": 1.5,
            "reasoning": "contain everything",
            "factors": ["llm_requested_network"],
        },
        risk_score=95,
        domain="devsecops",
        allowed_actions={"observe", "network_isolate", "block_deployment"},
        domain_actions={"observe", "block_deployment"},
        fallback_action="block_deployment",
        minimum_action="block_deployment",
        action_severity={"observe": 0, "network_isolate": 4, "block_deployment": 3},
        input_factors=["secret_exposure"],
    )

    assert result["schema"] == "redqueen.llm_decision.v1"
    assert result["requested_action_type"] == "network_isolate"
    assert result["action_type"] == "block_deployment"
    assert result["fallback_reason"] == "action_outside_domain"
    assert result["llm_action_accepted"] is False
    assert result["final_action_source"] == "guardrail"
    assert result["guardrail_decisions"][0] == {
        "guardrail": "domain_action_validation",
        "result": "fallback_applied",
        "from_action": "network_isolate",
        "to_action": "block_deployment",
        "reason": "action_outside_domain",
    }
    assert result["confidence"] == 0.99
    assert result["contract"]["domain"] == "devsecops"
    assert result["governance"]["schema"] == "vaelqorix.llm_governance.v1"
    assert result["governance"]["approved_for_ares"] is True
    assert "domain_action_validation" in result["governance"]["present_guardrails"]
    assert "secret_exposure" in result["factors"]
    assert "llm_requested_network" in result["factors"]


def test_llm_contract_marks_model_action_accepted_when_no_guardrail_changes():
    result = normalize_llm_decision(
        {"action_type": "require_mfa", "confidence": 0.7},
        risk_score=45,
        domain="identity",
        allowed_actions={"observe", "require_mfa", "revoke_session"},
        domain_actions={"observe", "require_mfa", "revoke_session"},
        fallback_action="require_mfa",
        minimum_action="require_mfa",
        action_severity={"observe": 0, "require_mfa": 1, "revoke_session": 2},
        input_factors=[],
    )

    assert result["action_type"] == "require_mfa"
    assert result["llm_action_accepted"] is True
    assert result["final_action_source"] == "llm"
    assert result["governance"]["approved_for_ares"] is True
    assert result["guardrail_decisions"][0]["result"] == "accepted"
    assert result["guardrail_decisions"][1]["result"] == "not_required"


def test_llm_governance_rejects_incomplete_contract():
    governance = assess_llm_contract(
        {
            "schema": "redqueen.llm_decision.v1",
            "domain": "identity",
            "confidence": 1.2,
            "guardrail_decisions": [],
        }
    )

    assert governance["approved_for_ares"] is False
    assert governance["confidence_valid"] is False
    assert "action_type" in governance["missing_fields"]
    assert "minimum_action_enforcement" in governance["missing_guardrails"]
