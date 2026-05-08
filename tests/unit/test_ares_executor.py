from app.ares.executor import execute_plan
from app.ares.planner import build_plan


def test_execute_plan_dry_run_does_not_execute_disruptive_action():
    plan = build_plan({"action_type": "network_isolate", "target": "asset-01"})

    result = execute_plan(plan, controls={"dry_run": True})

    assert result["status"] == "success"
    assert result["mode"] == "dry_run"
    assert result["rollback_available"] is False
    assert all(step["status"] == "planned" for step in result["executed_steps"])
    assert result["executed_steps"][1]["impact"] == "blocks network access for the target asset"


def test_build_plan_adds_operational_metadata():
    plan = build_plan(
        {
            "action_type": "network_isolate",
            "target": "asset-01",
            "risk_score": 96,
            "causal_chain": {"action_rationale": "contain lateral movement"},
        }
    )

    assert plan["requires_confirmation"] is True
    assert plan["rollback_strategy"] == "transactional_reverse_order"
    assert plan["max_criticality"] == 5
    assert plan["causal_summary"] == "contain lateral movement"
    assert plan["steps"][1]["rollback"] == "network_rollback"


def test_execute_plan_delegates_soar_steps(monkeypatch):
    calls = []

    def fake_dispatch(*, url, command, payload):
        calls.append({"url": url, "command": command, "payload": payload})
        return {"status": "ok", "command": command}

    monkeypatch.setattr("app.actions.soar.dispatch_command", fake_dispatch)
    plan = build_plan({"action_type": "soar_delegate", "target": "asset-01", "risk_score": 60})

    result = execute_plan(plan, controls={"threat_id": "threat-1"})

    assert result["status"] == "success"
    assert result["rollback_available"] is True
    assert [step["step"] for step in result["executed_steps"]] == ["open_ticket", "notify_soc"]
    assert [call["command"] for call in calls] == ["open_ticket", "notify_soc"]
    assert calls[0]["payload"]["threat_id"] == "threat-1"
