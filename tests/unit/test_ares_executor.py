from app.ares.executor import execute_plan


def test_execute_plan_dry_run_does_not_execute_disruptive_action():
    plan = {
        "action_type": "network_isolate",
        "target": "asset-01",
        "steps": [
            {"step": "resolve_target", "payload": {"target": "asset-01"}},
            {"step": "isolate_network", "payload": {"target": "asset-01"}},
        ],
    }

    result = execute_plan(plan, controls={"dry_run": True})

    assert result["status"] == "success"
    assert result["mode"] == "dry_run"
    assert result["rollback_available"] is False
    assert [step["status"] for step in result["executed_steps"]] == ["planned", "planned"]
