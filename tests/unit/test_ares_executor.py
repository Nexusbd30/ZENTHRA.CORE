from app.ares.executor import execute_plan
from app.ares.internal_firewall import evaluate_internal_firewall
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


def test_build_plan_supports_dns_firewall_block():
    plan = build_plan(
        {
            "action_type": "dns_firewall_block",
            "target": "malware.example",
            "risk_score": 88,
            "causal_chain": {"action_rationale": "block command and control DNS"},
        }
    )

    assert plan["requires_confirmation"] is True
    assert plan["rollback_strategy"] == "transactional_reverse_order"
    assert plan["max_criticality"] == 4
    assert [step["step"] for step in plan["steps"]] == [
        "resolve_dns_indicator",
        "apply_dns_firewall_block",
        "verify_dns_firewall_block",
    ]
    assert plan["steps"][1]["rollback"] == "dns_firewall_rollback"


def test_execute_plan_delegates_dns_firewall_block(monkeypatch):
    calls = []

    def fake_dispatch(*, url, command, payload):
        calls.append({"url": url, "command": command, "payload": payload})
        return {"status": "ok", "command": command}

    monkeypatch.setattr("app.actions.network.dispatch_command", fake_dispatch)
    monkeypatch.setattr("app.actions.network.settings.DNS_FIREWALL_CONTROL_URL", "https://dns-control.local")
    plan = build_plan({"action_type": "dns_firewall_block", "target": "malware.example"})

    result = execute_plan(
        plan,
        controls={
            "dns_firewall_provider": "umbrella",
            "threat_id": "threat-dns-1",
            "change_ticket": "CHG-DNS-1",
        },
    )

    assert result["status"] == "success"
    assert calls[1]["url"] == "https://dns-control.local"
    assert calls[1]["command"] == "apply_dns_firewall_block"
    assert calls[1]["payload"]["target"] == "malware.example"
    assert calls[1]["payload"]["provider"] == "umbrella"
    assert calls[1]["payload"]["threat_id"] == "threat-dns-1"


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


def test_execute_plan_delegates_crypto_rotation(monkeypatch):
    calls = []

    def fake_dispatch(*, url, command, payload):
        calls.append({"url": url, "command": command, "payload": payload})
        return {"status": "ok", "command": command}

    monkeypatch.setattr("app.actions.crypto.dispatch_command", fake_dispatch)
    plan = build_plan({"action_type": "crypto_rotate", "target": "vault/prod/api-key"})

    result = execute_plan(
        plan,
        controls={
            "threat_id": "threat-crypto-1",
            "key_id": "kms-key-01",
            "change_ticket": "CHG-CRYPTO-1",
        },
    )

    assert result["status"] == "success"
    assert result["rollback_available"] is True
    assert [step["step"] for step in result["executed_steps"]] == [
        "resolve_crypto_material",
        "rotate_crypto_material",
        "verify_rotation",
    ]
    assert calls[1]["command"] == "rotate_crypto_material"
    assert calls[1]["payload"]["key_id"] == "kms-key-01"
    assert calls[1]["payload"]["threat_id"] == "threat-crypto-1"


def test_internal_firewall_blocks_protected_disruptive_target_without_owner_approval():
    verdict = {
        "verdict_id": "v-fw-1",
        "action_type": "network_isolate",
        "target": "database-prod-01",
        "risk_score": 96,
        "execution_controls": {
            "mcp_tool_policy": {"allowed": True},
        },
    }
    plan = build_plan(verdict)

    decision = evaluate_internal_firewall(
        verdict=verdict,
        plan=plan,
        advisor_review={"safe_to_execute": True, "mcp_action_policy": {"allowed": True}},
        controls={
            "change_ticket": "CHG-1",
            "firewall_policy": {"protected_targets": ["database-prod-*"]},
        },
    )

    assert decision.allowed is False
    assert decision.code == "firewall_protected_target_control_missing"
    assert decision.severity == "critical"


def test_internal_firewall_allows_protected_target_with_required_controls():
    verdict = {
        "verdict_id": "v-fw-2",
        "action_type": "network_isolate",
        "target": "database-prod-01",
        "risk_score": 96,
        "execution_controls": {
            "mcp_tool_policy": {"allowed": True},
        },
    }
    plan = build_plan(verdict)

    decision = evaluate_internal_firewall(
        verdict=verdict,
        plan=plan,
        advisor_review={"safe_to_execute": True, "mcp_action_policy": {"allowed": True}},
        controls={
            "change_ticket": "CHG-1",
            "dependency_owner_approved": True,
            "firewall_policy": {"protected_targets": ["database-prod-*"]},
        },
    )

    assert decision.allowed is True
    assert decision.code == "ok"
