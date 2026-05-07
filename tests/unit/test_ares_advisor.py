from app.ares.advisor import review_plan
from app.ares.planner import build_plan


def test_ares_advisor_uses_llm_and_mcp_context(monkeypatch):
    monkeypatch.setattr(
        "app.ares.advisor.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"risk":"high","safe_to_execute":false,'
            '"required_safeguards":["peer_review"],'
            '"operator_notes":"MCP context indicates critical dependency",'
            '"mcp_used":true}'
        ),
    )

    verdict = {
        "verdict_id": "v-1",
        "target": "identity-api",
        "action_type": "identity_lockdown",
        "risk_score": 88,
        "requires_human": False,
        "causal_chain": {"impact": "credential abuse"},
    }
    plan = build_plan(verdict)

    review = review_plan(
        verdict=verdict,
        plan=plan,
        controls={
            "change_ticket": "CHG-1",
            "mcp_context": {"service_owner": "iam-team", "critical_dependency": True},
        },
    )

    assert review["risk"] == "high"
    assert review["safe_to_execute"] is False
    assert review["mcp_used"] is True
    assert "peer_review" in review["required_safeguards"]
    assert "operator_confirmation" in review["required_safeguards"]
    assert "mcp_context_reviewed" in review["required_safeguards"]
    assert "dependency_owner_review" in review["required_safeguards"]


def test_ares_advisor_cannot_mark_mcp_blocked_action_safe(monkeypatch):
    monkeypatch.setattr(
        "app.ares.advisor.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"risk":"medium","safe_to_execute":true,'
            '"required_safeguards":[],"operator_notes":"looks safe","mcp_used":true}'
        ),
    )

    verdict = {
        "verdict_id": "v-2",
        "target": "critical-db",
        "action_type": "network_isolate",
        "risk_score": 97,
        "requires_human": True,
        "causal_chain": {"impact": "data exfiltration"},
    }
    plan = build_plan(verdict)

    review = review_plan(
        verdict=verdict,
        plan=plan,
        controls={"mcp_context": {"blocked_actions": ["network_isolate"]}},
    )

    assert review["safe_to_execute"] is False
    assert review["mcp_action_policy"]["code"] == "mcp_action_blocked"
    assert "mcp_action_blocked" in review["required_safeguards"]
