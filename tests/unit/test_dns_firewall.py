from __future__ import annotations

import pytest

from app.ares.executor import execute_plan
from app.ares.planner import build_plan
from app.dns_firewall.contracts import DnsTargetError, normalize_target, stable_idempotency_key
from app.dns_firewall.service import create_pending_rule, list_rules, preflight_target


def test_normalize_domain_url_and_ip():
    assert normalize_target("HTTPS://Example.COM/path").value == "example.com"
    assert normalize_target("example.com.").value == "example.com"
    assert normalize_target("203.0.113.10").target_type == "ip"


@pytest.mark.parametrize(
    "target",
    ["", "localhost", "example..com", ".example.com", "-bad.example.com", "example.com-"]
)
def test_normalize_rejects_unsafe_targets(target):
    with pytest.raises(DnsTargetError):
        normalize_target(target)


def test_idempotency_key_is_stable_and_changes_with_scope():
    first = stable_idempotency_key(
        tenant_id="tenant-a",
        verdict_id="verdict-1",
        action="block",
        target="example.com",
        step="apply_dns_firewall_block",
    )
    assert first == stable_idempotency_key(
        tenant_id="tenant-a",
        verdict_id="verdict-1",
        action="block",
        target="example.com",
        step="apply_dns_firewall_block",
    )
    assert first != stable_idempotency_key(
        tenant_id="tenant-b",
        verdict_id="verdict-1",
        action="block",
        target="example.com",
        step="apply_dns_firewall_block",
    )


def test_preflight_requires_tenant_and_returns_normalized_target():
    plan = preflight_target(
        tenant_id="tenant-a",
        target="Example.COM.",
        provider="webhook",
        verdict_id="verdict-1",
    )
    assert plan["allowed"] is True
    assert plan["target"] == "example.com"
    assert plan["tenant_id"] == "tenant-a"
    assert len(str(plan["idempotency_key"])) == 64


def test_create_pending_rule_is_idempotent(db_session):
    first_rule, first_execution = create_pending_rule(
        db_session,
        tenant_id="tenant-a",
        target="Example.COM",
        provider="webhook",
        verdict_id="verdict-1",
    )
    second_rule, second_execution = create_pending_rule(
        db_session,
        tenant_id="tenant-a",
        target="example.com.",
        provider="webhook",
        verdict_id="verdict-1",
    )

    assert first_rule.rule_id == second_rule.rule_id
    assert first_execution.execution_id == second_execution.execution_id
    assert len(list_rules(db_session, tenant_id="tenant-a")) == 1


def test_ares_execution_updates_persistent_dns_state(db_session, monkeypatch):
    calls = []

    def fake_dispatch(*, url, command, payload):
        calls.append((url, command, payload))
        return {"status": "ok", "request_id": f"req-{len(calls)}"}

    monkeypatch.setattr("app.actions.network.dispatch_command", fake_dispatch)
    rule, execution = create_pending_rule(
        db_session,
        tenant_id="tenant-a",
        target="malware.example",
        provider="webhook",
        verdict_id="verdict-dns-1",
        change_ticket="CHG-DNS-1",
    )
    controls = {
        "tenant_id": "tenant-a",
        "dns_firewall_provider": "webhook",
        "dns_firewall_rule_id": rule.rule_id,
        "dns_firewall_execution_id": execution.execution_id,
        "dns_firewall_idempotency_key": execution.idempotency_key,
        "verdict_id": "verdict-dns-1",
        "threat_id": "threat-dns-1",
        "change_ticket": "CHG-DNS-1",
        "_dns_firewall_db": db_session,
    }

    result = execute_plan(
        build_plan({"action_type": "dns_firewall_block", "target": "malware.example"}),
        controls=controls,
    )

    db_session.refresh(rule)
    db_session.refresh(execution)
    assert result["status"] == "success"
    assert execution.status == "verified"
    assert rule.status == "verified"
    assert calls[1][2]["idempotency_key"] == execution.idempotency_key
