from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from shutil import rmtree
from uuid import uuid4

import httpx
import pytest
import requests
from fastapi import HTTPException

from app.ares.aggressive_containment import build_aggressive_containment
from app.ares.approval import build_approval_payload, verify_approval_payload
from app.ares.internal_firewall import evaluate_internal_firewall
from app.ares.kill_switch import (
    RedisKillSwitchStore,
    kill_switch_state,
    reset_kill_switch_store,
)
from app.ares.kill_switch import (
    set_kill_switch as set_ares_kill_switch,
)
from app.ares.memory import read_ares_memory
from app.ares.monitor import evaluate_ares_health
from app.ares.planner import build_plan
from app.ares.router import (
    ContainmentPlanRequest,
    EnterpriseActiveDefenseRequest,
    ResponseFabricRequest,
    RollbackRequest,
    ShieldPlanRequest,
    build_active_defense_plan,
    build_containment_plan,
    build_response_fabric_plan,
    build_shield_plan,
    get_ares_memory,
    get_operation_flow,
    read_execution,
    rollback_execution,
    set_kill_switch,
)
from app.connectors.registry import connector_execute_plan, connector_readiness
from app.connectors.router import (
    ConnectorExecuteRequest,
    ConnectorPreflightRequest,
    read_connector_readiness,
    read_connectors,
    run_connector_execute,
    run_connector_preflight,
)
from app.core.mcp_context import evaluate_mcp_action_policy, mcp_risk_factors, normalize_mcp_context
from app.core.rate_limit import RedisRateLimitStore
from app.core.replay_guard import RedisReplayGuardStore
from app.core.settings import Settings, _prefer_ipv4_loopback
from app.core.signing import sign_payload
from app.db.audit_store import (
    append_audit_record,
    query_audit_records,
    verify_aresx_audit_chain,
    verify_audit_chain,
)
from app.db.vector import LocalVectorStore, cosine_similarity, embed_text
from app.detection.entity_graph import build_entity_graph
from app.detection.ioc_enrichment import enrich_iocs
from app.health.checks import db_check, run_checks
from app.health.router import system_ready
from app.identity.entra import (
    build_entra_provider_evidence,
    build_entra_readiness,
    entra_replay_key,
    expected_entra_signature,
    normalize_entra_risk_event,
    verify_entra_webhook_signature,
)
from app.identity.entra_graph import dispatch_entra_graph_command
from app.identity.providers import (
    action_preflight_payload as identity_action_preflight_payload,
)
from app.identity.providers import (
    get_provider_capabilities as get_identity_provider_capabilities,
)
from app.identity.providers import (
    list_provider_capability_payloads as list_identity_provider_capability_payloads,
)
from app.identity.providers import (
    strongest_supported_identity_action,
    validate_identity_action,
    validate_identity_command,
)
from app.identity.service import (
    canonicalize_identity_signal,
    list_identity_event_timeline,
    persist_identity_event,
    summarize_identity_activity,
)
from app.ingestion.adapters.wazuh import adapt_wazuh_event
from app.models.audit_record import AuditRecord
from app.models.entity_profile import EntityProfile
from app.models.execution_result import ExecutionResult
from app.models.response_log import ResponseLog
from app.models.threat_event import ThreatEvent
from app.models.verdict import Verdict
from app.playbooks.contracts import Playbook, PlaybookStep, playbook_from_dict
from app.playbooks.engine import build_execution_plan
from app.playbooks.registry import get_playbook, list_playbooks, load_playbook, playbook_summary
from app.playbooks.router import PlaybookPreviewRequest, preview, read_playbooks
from app.playbooks.runtime import preview_playbook
from app.redqueen.policy_matrix import evaluate_policy
from app.redqueen.risk_scorer import score_perception
from app.redqueen.router import (
    AnticipationRequest,
    BridgeTraceRequest,
    StrategicAnticipationRequest,
    anticipate_attack,
    approve_aresx_verdict,
    read_aresx_verdict,
    read_entity_profile,
    read_vector_status,
    read_verdict,
    reject_aresx_verdict,
    strategic_anticipation,
    trace_bridge,
)
from app.redqueen.trainer import build_training_report
from app.redqueen.ueba import analyze_ueba_signals
from app.routers.monitoring_correlation import run_correlation, serialize_threat
from app.routers.monitoring_health import health_full
from app.runtime.router import EnqueueRequest, enqueue_playbook, runtime_status
from app.secops.contracts import DevSecOpsSignal
from app.secops.github import dispatch_github_command
from app.secops.providers import (
    action_preflight_payload as devsecops_action_preflight_payload,
)
from app.secops.providers import (
    get_provider_capabilities as get_devsecops_provider_capabilities,
)
from app.secops.providers import (
    strongest_supported_devsecops_action,
    validate_devsecops_action,
    validate_devsecops_command,
)
from app.secops.readiness import (
    build_all_readiness,
    build_execution_preflight,
    build_github_actions_readiness,
    build_redis_readiness,
    build_secops_integration_readiness,
    build_secret_backend_readiness,
    build_soc_webhook_readiness,
)
from app.secops.service import (
    build_security_event_export_payload,
    correlate_identity_devsecops,
    materialize_security_event_abuse,
    persist_devsecops_signal,
    persist_identity_pipeline_correlation_event,
    send_security_event_export_webhook,
    summarize_devsecops_signals,
    summarize_security_events,
)
from app.sensors.cloud_sensor.collector import collect_cloud_findings
from app.sensors.contracts import SensorFinding, severity_from_signals
from app.sensors.endpoint_agent.collector import collect_endpoint_findings
from app.sensors.k8s_sensor.collector import collect_k8s_findings
from app.sensors.network_sensor.collector import collect_network_findings
from app.sensors.router import SensorNormalizeRequest, normalize_sensor_event, sensor_status
from app.services.autonomy_service import AutonomyService
from app.services.prometheus_client import PrometheusClient
from app.services.runtime_log_service import _parse_log_line, list_runtime_logs


def test_backend_entrypoints_and_contract_modules_import_cleanly():
    module_names = [
        "app.db.base",
        "app.entrypoints.ares",
        "app.entrypoints.ingestion",
        "app.entrypoints.redqueen",
        "app.platform.contracts",
    ]

    imported = [import_module(name) for name in module_names]

    assert imported[0].__all__ == ["Base"]
    assert hasattr(imported[1], "app")
    assert hasattr(imported[2], "app")
    assert hasattr(imported[3], "app")
    assert hasattr(imported[4], "AgentRuntime")


def test_entity_graph_builds_nodes_edges_and_skips_empty_matches():
    graph = build_entity_graph(
        [
            {
                "entity_id": "host-1",
                "entity_type": "endpoint",
                "normalized_payload": {
                    "src_ip": "10.0.0.5",
                    "dst_ip": "198.51.100.10",
                    "domain": "callback.example",
                    "user": "alice",
                    "host": "workstation-7",
                },
            },
            {"entity_id": "", "normalized_payload": "not-a-dict"},
        ],
        [
            {"rule_id": "rq-001", "entity_id": "host-1"},
            {"rule_id": "", "entity_id": "host-2"},
        ],
    )

    node_ids = {node["id"] for node in graph["nodes"]}
    relationships = {edge["relationship"] for edge in graph["edges"]}

    assert {"host-1", "unknown", "10.0.0.5", "callback.example", "rq-001"} <= node_ids
    assert {"src_ip", "dst_ip", "domain", "user", "host", "matched"} <= relationships


def test_ioc_enrichment_deduplicates_ips_and_falls_back_to_event_country():
    enriched = enrich_iocs(
        {
            "event_id": "evt-1",
            "src_ip": "10.1.1.1",
            "dst_ip": "not-an-ip",
            "geo_country": "ES",
            "normalized_payload": {
                "src_ip": "10.1.1.1",
                "dst_ip": "8.8.8.8",
                "dns_query": "beacon.example",
                "asn": "AS15169",
            },
        }
    )

    assert enriched["event_id"] == "evt-1"
    assert {item["ip"] for item in enriched["ips"]} == {"10.1.1.1", "8.8.8.8"}
    assert enriched["domain"] == "beacon.example"
    assert enriched["asn"] == "AS15169"
    assert enriched["geo_country"] == "ES"


def test_ioc_enrichment_handles_empty_payload_and_invalid_ip():
    enriched = enrich_iocs({"event_id": "evt-2", "src_ip": "invalid", "normalized_payload": None})

    assert enriched == {
        "event_id": "evt-2",
        "ips": [],
        "domain": "",
        "asn": "",
        "geo_country": "",
    }


def test_playbook_engine_covers_equals_contains_min_and_gated_steps():
    playbook = Playbook(
        playbook_id="containment",
        name="Containment",
        description="Containment plan",
        version="1.0.0",
        steps=[
            PlaybookStep(
                step_id="block",
                connector="paloalto",
                action="block_ip",
                parameters={"ip": "198.51.100.10"},
                when={
                    "equals": {"incident.severity": "critical"},
                    "contains": {"incident.tags": "c2"},
                    "min": {"incident.score": 80},
                },
                requires_approval=True,
                retries=2,
                rollback="unblock_ip",
                on_success="ticket",
                on_failure="rollback",
            ),
            PlaybookStep(
                step_id="skip",
                connector="edr",
                action="isolate_host",
                when={"min": {"incident.score": "not-a-number"}},
            ),
        ],
    )

    plan = build_execution_plan(
        playbook,
        context={"incident": {"severity": "critical", "tags": ["c2"], "score": 95}},
        dry_run=True,
        approved=False,
    )
    ready_plan = build_execution_plan(
        playbook,
        context={"incident": {"severity": "critical", "tags": ["c2"], "score": 95}},
        dry_run=False,
        approved=True,
    )

    assert plan["approval_required"] is True
    assert plan["steps"][0]["status"] == "approval_required"
    assert plan["skipped"] == [{"step_id": "skip", "reason": "condition_not_met"}]
    assert ready_plan["steps"][0]["status"] == "ready"


def test_playbook_engine_rejects_nested_lookup_and_contains_string_miss():
    playbook = Playbook(
        playbook_id="branching",
        name="Branching",
        description="Branch coverage",
        version="1.0.0",
        steps=[
            PlaybookStep(
                step_id="bad-lookup",
                connector="case",
                action="open_case",
                when={"equals": {"incident.score.value": 10}},
            ),
            PlaybookStep(
                step_id="string-contains",
                connector="case",
                action="open_case",
                when={"contains": {"incident.summary": "credential"}},
            ),
        ],
    )

    plan = build_execution_plan(
        playbook,
        context={"incident": {"score": 10, "summary": "network scan"}},
    )

    assert [item["step_id"] for item in plan["skipped"]] == ["bad-lookup", "string-contains"]


def test_playbook_contracts_registry_runtime_and_router_paths(monkeypatch):
    tmp_path = Path(".test-data") / f"playbooks-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    playbook_file = tmp_path / "containment.json"
    try:
        playbook_file.write_text(
            """
            {
              "id": "pb-1",
              "version": "2.0.0",
              "name": "Contain",
              "description": "Containment",
              "triggers": ["c2", ""],
              "labels": {"tier": "critical"},
              "steps": [
                {
                  "id": "block_ip",
                  "action": "block_ip",
                  "connector": "paloalto",
                  "parameters": {"target": "198.51.100.8"},
                  "when": {"equals": {"severity": "critical"}},
                  "retries": 1,
                  "requires_approval": true,
                  "rollback": "unblock_ip",
                  "on_success": "case",
                  "on_failure": "rollback"
                },
                "ignored"
              ]
            }
            """,
            encoding="utf-8",
        )

        loaded = load_playbook(playbook_file)
        parsed = playbook_from_dict({"steps": "bad", "triggers": "bad", "labels": {"x": 1}})
        monkeypatch.setattr("app.playbooks.registry.PLAYBOOK_ROOT", tmp_path)
        monkeypatch.setattr("app.playbooks.runtime.get_playbook", lambda playbook_id: loaded)
        monkeypatch.setattr("app.playbooks.router.list_playbooks", lambda: [loaded])

        missing_root = tmp_path / "missing"
        listed = list_playbooks(tmp_path)
        missing = list_playbooks(missing_root)
        found = get_playbook("pb-1", tmp_path)
        not_found = get_playbook("missing", tmp_path)
        runtime_preview = preview_playbook(
            playbook_id="pb-1",
            context={"severity": "critical"},
            approved=True,
        )
        router_preview = preview(
            "pb-1",
            PlaybookPreviewRequest(context={"severity": "critical"}, approved=True),
        )

        assert parsed.steps == []
        assert parsed.triggers == []
        assert listed == [loaded]
        assert missing == []
        assert found == loaded
        assert not_found is None
        assert playbook_summary(loaded)["step_count"] == 1
        assert read_playbooks()["items"][0]["playbook_id"] == "pb-1"
        assert runtime_preview["status"] == "ok"
        assert router_preview["plan"]["steps"][0]["status"] == "planned"

        monkeypatch.setattr("app.playbooks.runtime.get_playbook", lambda playbook_id: None)
        assert preview_playbook(playbook_id="missing", context={}) == {
            "status": "not_found",
            "playbook_id": "missing",
        }
    finally:
        rmtree(tmp_path, ignore_errors=True)


def test_connector_stubs_registry_and_router_paths():
    stub_modules = [
        "app.connectors.case.jira",
        "app.connectors.edr.crowdstrike",
        "app.connectors.edr.defender",
        "app.connectors.edr.sentinelone",
        "app.connectors.firewall.cisco",
        "app.connectors.firewall.fortinet",
        "app.connectors.firewall.paloalto",
        "app.connectors.redhat.acs",
        "app.connectors.redhat.ansible",
        "app.connectors.redhat.openshift",
        "app.connectors.redhat.quay",
        "app.connectors.siem.qradar",
        "app.connectors.siem.sentinel",
        "app.connectors.siem.splunk",
        "app.connectors.soar.servicenow",
    ]

    capabilities = [import_module(name).CAPABILITY for name in stub_modules]
    ready = connector_readiness(
        "paloalto",
        {"PALOALTO_API_KEY": "secret", "PALOALTO_BASE_URL": "https://fw.example"},
    )
    unknown_ready = connector_readiness("unknown")
    blocked = connector_execute_plan(
        "paloalto",
        action="unsupported",
        target="198.51.100.8",
    )
    delegated = connector_execute_plan(
        "paloalto",
        action="block_ip",
        target="198.51.100.8",
        dry_run=False,
        change_ticket="CHG-1",
    )

    assert {capability.provider for capability in capabilities} >= {"paloalto", "crowdstrike"}
    assert read_connectors()["items"]
    assert ready["ready"] is True
    assert unknown_ready["code"] == "provider_unknown"
    assert connector_execute_plan("unknown", action="block_ip", target="x")["status"] == "failed"
    assert blocked["status"] == "blocked"
    assert delegated["status"] == "delegated"
    assert read_connector_readiness("missing")["ready"] is False
    assert (
        run_connector_preflight(
            "paloalto",
            ConnectorPreflightRequest(
                action="block_ip",
                target="198.51.100.8",
                change_ticket="CHG-1",
            ),
        )["allowed"]
        is True
    )
    assert (
        run_connector_execute(
            "paloalto",
            ConnectorExecuteRequest(
                action="block_ip",
                target="198.51.100.8",
                change_ticket="CHG-1",
                dry_run=True,
            ),
        )["status"]
        == "planned"
    )


def test_mcp_context_normalizes_edges_and_blocks_policy():
    context = normalize_mcp_context(
        {
            "source": "mcp",
            "target": "api",
            "critical_dependency": "yes",
            "business_criticality": "critical",
            "asset_tier": "prod",
            "blast_radius": "enterprise",
            "exposed_to_internet": "on",
            "active_incident_count": "bad",
            "blocked_actions": ["block_ip"],
            "allowed_actions": ["observe"],
            "tools": ["identity.lookup"],
            "tool_results": ["ok"],
            "evidence_refs": ["case-1"],
        }
    )

    factors = mcp_risk_factors(context)
    blocked = evaluate_mcp_action_policy("block_ip", context)
    not_allowed = evaluate_mcp_action_policy("isolate_endpoint", context)
    allowed = evaluate_mcp_action_policy("observe", context)

    assert "mcp:critical_dependency" in factors
    assert "mcp:internet_exposed" in factors
    assert "mcp:tool_results_present" in factors
    assert blocked["code"] == "mcp_action_blocked"
    assert not_allowed["code"] == "mcp_action_not_allowed"
    assert allowed["allowed"] is True


def test_redis_rate_limit_store_with_fake_client(monkeypatch):
    class FakePipeline:
        def __init__(self, client):
            self.client = client
            self.commands = []

        def zremrangebyscore(self, *args):
            self.commands.append(("zremrangebyscore", args))
            return self

        def zcard(self, key):
            self.commands.append(("zcard", key))
            return self

        def zadd(self, key, values):
            self.commands.append(("zadd", key, values))
            self.client.count += 1
            return self

        def expire(self, *args):
            self.commands.append(("expire", args))
            return self

        def execute(self):
            if any(command[0] == "zadd" for command in self.commands):
                return [1, True, self.client.count]
            return [0, self.client.count]

    class FakeRedisClient:
        count = 0

        def pipeline(self):
            return FakePipeline(self)

        def zrange(self, *args, **kwargs):
            return [("oldest", 1_000)]

        def scan_iter(self, match):
            return ["one", "two"]

        def delete(self, key):
            self.deleted.append(key)

        def __init__(self):
            self.deleted = []

    class FakeRedis:
        created = FakeRedisClient()

        class Redis:
            @staticmethod
            def from_url(*args, **kwargs):
                return FakeRedis.created

    monkeypatch.setattr("app.core.rate_limit.redis", FakeRedis)
    store = RedisRateLimitStore(url="redis://example", key_prefix=":prefix:")

    first = store.check(key="actor", limit=1, window_seconds=60)
    second = store.check(key="actor", limit=1, window_seconds=60)
    store.reset()

    assert first.allowed is True
    assert second.allowed is False
    assert second.retry_after_seconds >= 1
    assert FakeRedis.created.deleted == ["one", "two"]


def test_redis_replay_guard_store_with_fake_client(monkeypatch):
    class FakeClient:
        def __init__(self):
            self.keys = set()
            self.deleted = []

        def set(self, key, value, nx, ex):
            assert value == "1"
            assert nx is True
            assert ex == 5
            if key in self.keys:
                return False
            self.keys.add(key)
            return True

        def scan_iter(self, match):
            return list(self.keys)

        def delete(self, key):
            self.deleted.append(key)

    class FakeRedis:
        created = FakeClient()

        class Redis:
            @staticmethod
            def from_url(*args, **kwargs):
                return FakeRedis.created

    monkeypatch.setattr("app.core.replay_guard.redis", FakeRedis)
    store = RedisReplayGuardStore(url="redis://example", key_prefix=":prefix:")

    accepted = store.check(key="payload", ttl_seconds=5)
    replay = store.check(key="payload", ttl_seconds=5)
    store.reset()

    assert accepted.accepted is True
    assert replay.accepted is False
    assert FakeRedis.created.deleted == ["prefix:replay:payload"]


def test_audit_store_query_and_corruption_paths(db_session):
    first = append_audit_record(
        db_session,
        verdict_id="verdict-audit",
        actor="redqueen",
        actor_role="system",
        tenant_id="tenant-a",
        capability="risk:score",
        request_id="req-audit",
        action="verdict_issued",
        result={"status": "ok"},
    )
    second = append_audit_record(
        db_session,
        verdict_id="verdict-audit",
        actor="ares",
        actor_role="system",
        tenant_id="tenant-a",
        capability="ares:execute",
        request_id="req-audit-2",
        action="execution_completed",
        result={"status": "ok"},
    )

    queried = query_audit_records(
        db_session,
        verdict_id="verdict-audit",
        event_type="execution_completed",
        actor="ares",
        tenant_id="tenant-a",
        capability="ares:execute",
        from_sequence=second.sequence_number,
    )
    valid_aresx = verify_aresx_audit_chain(db_session, from_sequence=2)
    valid_legacy = verify_audit_chain(db_session)

    assert queried == [second]
    assert valid_aresx["valid"] is True
    assert valid_legacy["valid"] is True

    second.previous_chain_hash = "broken"
    db_session.commit()
    assert verify_aresx_audit_chain(db_session, from_sequence=2)["reason"] == (
        "previous_chain_hash_mismatch"
    )

    second.previous_chain_hash = first.chain_hash
    second.payload = "{bad-json"
    db_session.commit()
    assert verify_aresx_audit_chain(db_session, from_sequence=2)["reason"] == (
        "content_hash_mismatch"
    )


@dataclass
class _FailingDb:
    def execute(self, _query):
        raise RuntimeError("database unavailable")


@dataclass
class _HealthyDb:
    def execute(self, _query):
        return object()


def test_health_checks_cover_up_and_down_paths():
    assert db_check(_HealthyDb()) == {"name": "database", "status": "up"}

    down = db_check(_FailingDb())
    degraded = run_checks(_FailingDb())
    ready = system_ready(_HealthyDb())
    not_ready = system_ready(_FailingDb())

    assert down["status"] == "down"
    assert "database unavailable" in down["error"]
    assert degraded["overall"] == "degraded"
    assert ready["status"] == "ready"
    assert not_ready["status"] == "degraded"


def test_secops_devsecops_branches_and_correlation_thresholds(db_session):
    now = datetime.now(UTC)
    pipeline_event, duplicate = persist_devsecops_signal(
        db_session,
        DevSecOpsSignal(
            provider="github_actions",
            event_id="pipeline-entity",
            event_type="deployment_anomaly",
            pipeline_id="pipe-1",
            severity=7,
            occurred_at=now,
        ),
    )
    artifact_event, _ = persist_devsecops_signal(
        db_session,
        DevSecOpsSignal(
            provider="github_actions",
            event_id="artifact-entity",
            event_type="container_vuln",
            artifact="registry/app@sha256:abc",
            severity=5,
            high_count=1,
        ),
    )
    actor_event, _ = persist_devsecops_signal(
        db_session,
        DevSecOpsSignal(
            provider="github_actions",
            event_id="actor-entity",
            event_type="pipeline_identity_risk",
            actor_identity="builder@corp.com",
            severity=4,
            privileged_actor=True,
        ),
    )
    service_event, _ = persist_devsecops_signal(
        db_session,
        DevSecOpsSignal(
            provider="jenkins",
            event_id="service-entity",
            event_type="sast_finding",
            severity=1,
        ),
    )
    bad_json_event = ThreatEvent(
        source="devsecops:broken",
        event_id="broken-json",
        event_type="sast_finding",
        severity=1,
        entity_id="broken",
        entity_type="service",
        normalized_payload="{bad-json",
        normalized="{bad-json",
        risk_score=5,
    )
    db_session.add(bad_json_event)
    db_session.commit()

    low = correlate_identity_devsecops(db_session, actor_identity="nobody@corp.com")
    medium_event = ThreatEvent(
        source="identity:entra",
        event_id="identity-medium",
        event_type="login_anomaly",
        severity=4,
        entity_id="user:release@corp.com",
        entity_type="user",
        normalized_payload=json.dumps({"signals": []}),
        risk_score=40,
    )
    medium_devsecops = ThreatEvent(
        source="devsecops:github_actions",
        event_id="medium-devsecops",
        event_type="sast_finding",
        severity=4,
        entity_id="pipeline:pipe-medium",
        entity_type="pipeline",
        normalized_payload=json.dumps(
            {"actor_identity": "release@corp.com", "devsecops_context": {"signals": []}}
        ),
        risk_score=40,
    )
    high_devsecops = ThreatEvent(
        source="devsecops:github_actions",
        event_id="high-devsecops",
        event_type="dependency_vuln",
        severity=7,
        entity_id="pipeline:pipe-high",
        entity_type="pipeline",
        normalized_payload=json.dumps(
            {"actor_identity": "ops@corp.com", "devsecops_context": {"signals": []}}
        ),
        risk_score=71,
    )
    quarantine_devsecops = ThreatEvent(
        source="devsecops:github_actions",
        event_id="quarantine-devsecops",
        event_type="container_vuln",
        severity=8,
        entity_id="artifact:image",
        entity_type="artifact",
        normalized_payload=json.dumps(
            {"actor_identity": "image@corp.com", "devsecops_context": {"signals": []}}
        ),
        risk_score=83,
    )
    db_session.add_all([medium_event, medium_devsecops, high_devsecops, quarantine_devsecops])
    db_session.commit()

    medium = correlate_identity_devsecops(db_session, actor_identity="release@corp.com")
    high = correlate_identity_devsecops(db_session, actor_identity="ops@corp.com")
    quarantine = correlate_identity_devsecops(db_session, actor_identity="image@corp.com")
    non_correlated_event, _, non_correlated = persist_identity_pipeline_correlation_event(
        db_session,
        actor_identity="nobody@corp.com",
    )

    assert duplicate is False
    assert pipeline_event.entity_id == "pipeline:pipe-1"
    assert artifact_event.entity_id == "artifact:registry/app@sha256:abc"
    assert actor_event.entity_id == "user:builder@corp.com"
    assert service_event.entity_id == "devsecops:jenkins"
    assert summarize_devsecops_signals(db_session)["count"] >= 4
    assert low["recommended_action"] == "observe"
    assert medium["recommended_action"] == "require_release_approval"
    assert high["recommended_action"] == "revoke_pipeline_token"
    assert quarantine["recommended_action"] == "quarantine_artifact"
    assert non_correlated_event is None
    assert non_correlated["correlated"] is False


def test_secops_materialization_skips_below_threshold_and_security_filters(db_session):
    append_audit_record(
        db_session,
        verdict_id="identity:entra:webhook",
        actor="monitor",
        actor_role="internal",
        tenant_id="tenant-below",
        capability="identity:triage",
        request_id="req-below",
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": "invalid_signature",
            "status_code": 401,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": "below-1",
            "client_ip": "203.0.113.100",
            "payload_sha256": "belowhash",
            "secrets_exposed": False,
        },
    )
    db_session.add(
        AuditRecord(
            verdict_id="bad-payload",
            event_type="identity_entra_webhook_rejected",
            tenant_id="tenant-below",
            capability="identity:triage",
            payload="{bad-json",
            result="{bad-json",
        )
    )
    db_session.commit()

    filtered = summarize_security_events(
        db_session,
        event_type="identity_entra_webhook_rejected",
        reason="not-the-reason",
        tenant_id="tenant-below",
    )
    materialized = materialize_security_event_abuse(db_session, min_count=2, limit=20)

    assert filtered["count"] == 0
    item = next(item for item in materialized["items"] if item["tenant_id"] == "tenant-below")
    assert item["status"] == "below_threshold"
    assert materialized["skipped"] >= 1


def test_secops_export_webhook_not_configured_and_failure(monkeypatch, db_session):
    monkeypatch.setattr("app.secops.service.settings.SOC_WEBHOOK_URL", "")
    assert send_security_event_export_webhook({"contract": "soc_case.v1"})["status"] == (
        "not_configured"
    )

    monkeypatch.setattr("app.secops.service.settings.SOC_WEBHOOK_URL", "https://soc.example/hook")
    monkeypatch.setattr("app.secops.service.settings.SOC_WEBHOOK_TIMEOUT_SEC", 1)

    def failing_post(*_args, **_kwargs):
        raise requests.RequestException("network closed")

    monkeypatch.setattr("app.secops.service.requests.post", failing_post)
    payload = build_security_event_export_payload(db_session, send=True)

    assert payload["delivery"]["status"] == "failed"
    assert payload["delivery"]["ready_to_send"] is True
    assert "network closed" in payload["delivery"]["detail"]


def test_ares_and_redqueen_router_edges(monkeypatch, db_session):
    verdict = Verdict(
        verdict_id="verdict-router",
        target="srv-router",
        action_type="observe",
        primary_action="observe",
        recommended_actions='["observe"]',
        factors='["factor-a"]',
        xai_explanation="{bad-json",
        risk_score=25,
        confidence=0.7,
        status="pending",
    )
    profile = EntityProfile(
        entity_id="srv-router",
        entity_type="host",
        baseline_vector="[1,2]",
        feature_stats='{"cpu": 0.5}',
        anomaly_score=0.2,
        risk_score=25,
        risk_level="low",
        risk_factors='["known-good"]',
        observed_mitre_tags='["T1059"]',
        event_count=3,
    )
    execution = ExecutionResult(
        id="exec-router",
        verdict_id="verdict-router",
        ares_id="ares-1",
        action_type="observe",
        target_entity="srv-router",
        target_system="linux",
        status="success",
        pre_state="{bad-json",
        post_state='{"state":"ok"}',
        evidence='["evidence-a"]',
    )
    db_session.add_all([verdict, profile, execution])
    db_session.commit()

    monkeypatch.setattr("app.ares.router.AutonomyService.get_ares_memory", lambda *_args, **_kw: {"ok": True})

    assert set_kill_switch("bad")["status"] == "error"
    assert get_operation_flow()["name"] == "alert_to_evidence"
    assert build_shield_plan(ShieldPlanRequest(target="srv", risk_score=70))["schema"].endswith(
        "os_business_shield.v1"
    )
    assert build_containment_plan(ContainmentPlanRequest(verdict={"target": "srv"}))[
        "schema"
    ].endswith("aggressive_containment.v1")
    assert build_active_defense_plan(EnterpriseActiveDefenseRequest(verdict={"target": "srv"}))[
        "schema"
    ].endswith("enterprise_active_defense.v1")
    assert build_response_fabric_plan(ResponseFabricRequest(verdict={"target": "srv"}))[
        "schema"
    ].endswith("response_fabric.v1")
    assert read_execution("missing", db_session)["status"] == "not_found"
    assert read_execution("exec-router", db_session)["pre_state"] == {}
    rolled = rollback_execution(
        "exec-router",
        RollbackRequest(reason="test rollback", actor="analyst"),
        db_session,
    )
    assert rolled["status"] == "rolled_back"
    assert rollback_execution("missing", RollbackRequest(reason="missing"), db_session)["status"] == (
        "not_found"
    )
    assert get_ares_memory("srv-router", db=db_session)["ok"] is True

    assert anticipate_attack(AnticipationRequest(target="srv", risk_score=80))["schema"].endswith(
        "anticipation.v1"
    )
    assert trace_bridge(BridgeTraceRequest(target="srv", factors=["c2"]))["schema"].endswith(
        "bridge_trace.v1"
    )
    assert strategic_anticipation(StrategicAnticipationRequest(target="srv", risk_score=90))[
        "schema"
    ].endswith("strategic_anticipation.v1")
    assert read_aresx_verdict("missing", db_session)["status"] == "not_found"
    assert read_aresx_verdict("verdict-router", db_session)["recommended_actions"] == ["observe"]
    assert approve_aresx_verdict("missing", db_session)["status"] == "not_found"
    assert reject_aresx_verdict("missing", db_session)["status"] == "not_found"
    assert read_verdict("missing", db_session)["status"] == "not_found"
    assert read_verdict("verdict-router", db_session)["target"] == "srv-router"
    assert read_entity_profile("missing", db_session)["status"] == "not_found"
    assert read_entity_profile("srv-router", db_session)["risk_factors"] == ["known-good"]
    assert read_vector_status()["provider"] == "local"


def test_autonomy_service_static_edges(monkeypatch, db_session):
    db_session.add(
        ThreatEvent(
            id="event-autonomy-bad-json",
            source="sensor:endpoint",
            event_id="event-autonomy-bad-json",
            event_type="process_anomaly",
            severity=4,
            entity_id="host-auto",
            entity_type="endpoint",
            mitre_tags="{bad-json",
            normalized_payload="{bad-json",
            normalized="{bad-json",
            risk_score=42,
        )
    )
    db_session.commit()

    assert AutonomyService.get_verdict(db_session, "missing") is None
    assert AutonomyService.get_ares_memory(db_session, "missing")["items"] == []
    assert AutonomyService.issue_verdict_from_threat(db_session, threat_id=999999)["status"] == (
        "not_found"
    )
    assert AutonomyService._risk_level(40) == "medium"
    assert AutonomyService._risk_level(10) == "low"
    assert AutonomyService._rag_domain({"source": "identity:entra"}) == "identity"
    assert AutonomyService._rag_domain({"source": "devsecops:github_actions"}) == "devsecops"
    factors, payload = AutonomyService._enrich_with_rag(
        perception={"event_type": "login"},
        factors=["base"],
        controls={"rag_disabled": True},
    )
    perception = AutonomyService._threat_event_perception(
        db_session.get(ThreatEvent, "event-autonomy-bad-json"),
        db_session,
    )

    assert factors == ["base"]
    assert payload == {}
    assert perception["mitre_tags"] == []
    assert perception["normalized_payload"] == {}


def test_autonomy_execute_internal_firewall_rejection(monkeypatch, db_session):
    verdict = {
        "verdict_id": "verdict-firewall-reject",
        "target": "protected-db",
        "action_type": "network_isolate",
        "primary_action": "network_isolate",
        "risk_score": 88,
        "confidence": 0.9,
        "requires_human": False,
        "timestamp": datetime.now(UTC).isoformat(),
        "factors": ["protected_target"],
        "execution_controls": {
            "change_ticket": "CHG-FIREWALL-1",
            "mcp_context": {"blocked_actions": ["network_isolate"]},
        },
    }
    verdict["signature"] = sign_payload(verdict)

    result = AutonomyService.execute_verdict(db_session, verdict=verdict, human_approved=True)

    assert result["status"] == "rejected"
    assert result["code"] == "mcp_action_blocked"


@pytest.mark.asyncio
async def test_monitoring_router_http_edges(monkeypatch, db_session):
    import app.routers.monitoring as monitoring

    class FakeResponse:
        def __init__(self, payload=None, status_code=200, text="bad"):
            self._payload = payload or {"status": "success"}
            self.status_code = status_code
            self.text = text

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "bad status",
                    request=httpx.Request("GET", "https://prom.example"),
                    response=httpx.Response(self.status_code, text=self.text),
                )

    class SuccessClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return FakeResponse({"data": {"result": [{"value": [1, "2.5"]}]}})

    class RequestErrorClient(SuccessClient):
        async def get(self, *args, **kwargs):
            raise httpx.RequestError("offline", request=httpx.Request("GET", "https://x"))

    class StatusErrorClient(SuccessClient):
        async def get(self, *args, **kwargs):
            return FakeResponse(status_code=500, text="boom")

    monkeypatch.setattr(monitoring.httpx, "AsyncClient", SuccessClient)
    monitoring._PROM_CACHE.clear()
    assert (await monitoring.get_alerts())["data"]["result"][0]["value"][1] == "2.5"
    assert (await monitoring.monitoring_health())["status"] == "ok"
    assert (await monitoring.prom_query(q="up"))["data"]["result"][0]["value"][1] == "2.5"
    assert (await monitoring.get_alerts_realtime())["data"]["result"][0]["value"][1] == "2.5"
    assert monitoring.debug_alerts_base()["PROMETHEUS_BASE"]
    readiness = monitoring._production_readiness_report()
    assert "ai" in readiness
    assert "ares" in readiness
    assert monitoring._first_scalar([]) is None
    assert monitoring._first_scalar([{"value": [1, "nan"]}]) is None
    assert monitoring._first_scalar([{"value": [1, "bad"]}]) is None
    assert (await monitoring._first_prometheus_scalar(["up"]))["available"] is True

    monkeypatch.setattr(monitoring.httpx, "AsyncClient", RequestErrorClient)
    monitoring._PROM_CACHE.clear()
    with pytest.raises(HTTPException):
        await monitoring.get_alerts()
    with pytest.raises(HTTPException):
        await monitoring.monitoring_health()
    with pytest.raises(HTTPException):
        await monitoring.prom_query(q="up")
    assert (await monitoring.list_windows_nics())["errors"]
    assert await monitoring.get_alerts_realtime() == []
    assert (await monitoring._first_prometheus_scalar(["up"]))["available"] is False

    monkeypatch.setattr(monitoring.httpx, "AsyncClient", StatusErrorClient)
    monitoring._PROM_CACHE.clear()
    assert await monitoring.get_alerts_realtime() == []
    with pytest.raises(HTTPException):
        await monitoring.list_windows_nics()


def test_sensor_collectors_and_router_normalize_real_findings():
    endpoint = collect_endpoint_findings(
        {
            "host": "workstation-1",
            "process": "mimikatz.exe",
            "command_line": "powershell -enc AAA",
            "file_path": "c:\\windows\\system32\\config\\sam",
            "auth_failures": 7,
            "outbound_ip": "198.51.100.10",
        }
    )
    network = collect_network_findings(
        {
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.10",
            "dst_port": 8443,
            "connection_count": 5,
            "dns_query": "beacon.callback.example",
            "unique_hosts": 11,
            "geo_country": "ES",
        }
    )
    cloud = collect_cloud_findings(
        {
            "event_name": "IAM.CreateAccessKey",
            "actor": "alice",
            "resource": "iam:user/alice",
            "mfa_present": False,
            "src_ip": "203.0.113.20",
            "cloud_provider": "aws",
        }
    )
    k8s = collect_k8s_findings(
        {
            "verb": "create",
            "resource": "pods",
            "namespace": "prod",
            "user": "system:serviceaccount:prod:deploy",
            "privileged": True,
        }
    )
    custom = SensorFinding(
        sensor="native_test",
        event_type="test",
        severity=20,
        entity_id="entity",
        entity_type="service",
    )

    unsupported = normalize_sensor_event(SensorNormalizeRequest(sensor="unknown", payload={}))
    normalized = normalize_sensor_event(
        SensorNormalizeRequest(sensor="endpoint", payload={"process": "rundll32"})
    )

    assert sensor_status()["status"] == "enabled"
    assert "credential_dumping" in endpoint[0].signals
    assert "lateral_movement" in network[0].signals
    assert "identity_mfa_absent" in cloud[0].signals
    assert "k8s_privileged_pod" in k8s[0].signals
    assert custom.to_aresx_event()["severity"] == 10
    assert severity_from_signals(["unknown"], base=0) == 1
    assert unsupported["status"] == "unsupported_sensor"
    assert normalized["status"] == "ok"
    assert normalized["aresx_events"][0]["source"] == "native_endpoint_agent"


def test_identity_normalization_provider_readiness_and_timeline(monkeypatch, db_session):
    payload = {
        "id": "entra-risk-1",
        "riskEventType": "tokenReplay",
        "userPrincipalName": "admin@corp.com",
        "riskLevel": "high",
        "riskState": "confirmedCompromised",
        "isPrivileged": True,
        "mfaSatisfied": False,
        "createdDateTime": "2026-08-16T10:00:00Z",
        "location": {"countryOrRegion": "ES", "city": "Madrid"},
        "ipAddress": "203.0.113.44",
    }
    signal = normalize_entra_risk_event(payload)
    canonical = canonicalize_identity_signal(signal)
    event, duplicate = persist_identity_event(db_session, signal)
    duplicate_event, is_duplicate = persist_identity_event(db_session, signal)
    bad_json = ThreatEvent(
        source="identity:entra",
        event_id="bad-json-identity",
        event_type="login_failure",
        severity=3,
        entity_id="user:admin@corp.com",
        entity_type="user",
        mitre_tags="{bad-json",
        normalized_payload="{bad-json",
        normalized="{bad-json",
        risk_score=20,
    )
    db_session.add(bad_json)
    db_session.commit()

    body = b'{"id":"entra-risk-1"}'
    signature = expected_entra_signature(body, "secret", "1000")
    monkeypatch.setattr("app.identity.entra.settings.ENTRA_WEBHOOK_SECRET", "secret")
    monkeypatch.setattr("app.identity.entra.settings.ENTRA_WEBHOOK_MAX_SKEW_SEC", 60)
    monkeypatch.setattr("app.identity.entra.time.time", lambda: 1000.0)
    evidence = build_entra_provider_evidence(payload=payload, body=body, timestamp="1000")
    ready = build_entra_readiness()

    assert signal.event_type == "token_reuse"
    assert signal.severity == 10
    assert canonical["entity_id"] == "user:admin@corp.com"
    assert event.id == duplicate_event.id
    assert duplicate is False
    assert is_duplicate is True
    assert summarize_identity_activity(db_session, entity_id="user:admin@corp.com")[
        "risk_level"
    ] == "critical"
    assert list_identity_event_timeline(db_session, entity_id="user:admin@corp.com")["count"] == 2
    assert entra_replay_key(body=body, signature=signature, timestamp="1000")
    assert verify_entra_webhook_signature(body, signature, "1000") is True
    assert verify_entra_webhook_signature(body, "bad", "1000") is False
    assert verify_entra_webhook_signature(body, signature, None) is False
    assert evidence["signature"]["verified"] is True
    assert ready["provider"] == "entra"
    assert get_identity_provider_capabilities("github").provider == "github"
    assert list_identity_provider_capability_payloads()
    assert identity_action_preflight_payload("active_directory", "identity_lockdown", 90)[
        "adjusted"
    ] is True
    assert strongest_supported_identity_action("missing", 99) == "soar_delegate"
    assert validate_identity_command("entra", "identity.resolve").provider == "entra"
    assert validate_identity_action("entra", "identity_lockdown").provider == "entra"
    with pytest.raises(ValueError):
        get_identity_provider_capabilities("missing")
    with pytest.raises(ValueError):
        validate_identity_command("auth0", "identity.degrade_privileges")


def test_secops_provider_readiness_and_github_dispatch(monkeypatch):
    monkeypatch.setattr("app.secops.readiness.settings.REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr("app.secops.readiness.settings.SOC_WEBHOOK_URL", "https://soc.example/hook")
    monkeypatch.setattr("app.secops.readiness.settings.SOC_WEBHOOK_TOKEN", "token")
    monkeypatch.setattr("app.secops.readiness.settings.SOC_WEBHOOK_HMAC_SECRET", "hmac")
    monkeypatch.setattr("app.secops.readiness.settings.GITHUB_TOKEN", "gh-token")
    monkeypatch.setattr("app.secops.readiness.settings.GITHUB_API_BASE_URL", "https://api.github.com")
    monkeypatch.setattr("app.secops.readiness.settings.GITHUB_TOKEN_SECRET_NAMES", "PIPELINE_TOKEN")
    monkeypatch.setattr(
        "app.secops.readiness.rate_limit_backend_status",
        lambda: {"backend": "redis"},
    )
    monkeypatch.setattr(
        "app.secops.readiness.replay_guard_backend_status",
        lambda: {"backend": "redis"},
    )

    class FakeRedisClient:
        def ping(self):
            return True

    class FakeRedisModule:
        class Redis:
            @staticmethod
            def from_url(*_args, **_kwargs):
                return FakeRedisClient()

    monkeypatch.setitem(__import__("sys").modules, "redis", FakeRedisModule)

    assert get_devsecops_provider_capabilities("jenkins").provider == "jenkins"
    assert strongest_supported_devsecops_action("unknown", 99) == "soar_delegate"
    assert validate_devsecops_command("github_actions", "devsecops.resolve_pipeline").provider == (
        "github_actions"
    )
    assert validate_devsecops_action("github_actions", "block_deployment").provider == (
        "github_actions"
    )
    assert devsecops_action_preflight_payload("sonarqube", "block_deployment")[
        "recommended_action"
    ] == "require_release_approval"
    with pytest.raises(ValueError):
        get_devsecops_provider_capabilities("unknown")
    with pytest.raises(ValueError):
        validate_devsecops_command("sonarqube", "devsecops.block_deployment")

    assert build_redis_readiness()["status"] == "ready"
    assert build_soc_webhook_readiness()["status"] == "ready"
    assert build_github_actions_readiness()["configured"] is True
    assert build_secret_backend_readiness()["secrets_exposed"] is False
    assert build_secops_integration_readiness("unknown")["status"] == "unknown_provider"
    assert build_all_readiness()["module"] == "secops"
    assert build_execution_preflight(
        provider="github_actions",
        action_type="revoke_pipeline_token",
        execution_controls={"dry_run": False, "change_ticket": "CHG-1"},
    )["allowed"] is True

    class FakeResponse:
        status_code = 200
        headers = {"x-github-request-id": "REQ-1"}

        def json(self):
            return {"visibility": "private", "default_branch": "main"}

        def raise_for_status(self):
            return None

    class DeleteResponse(FakeResponse):
        status_code = 204

    calls = []

    def fake_get(url, **kwargs):
        calls.append(("get", url, kwargs))
        return FakeResponse()

    def fake_put(url, **kwargs):
        calls.append(("put", url, kwargs))
        return FakeResponse()

    def fake_delete(url, **kwargs):
        calls.append(("delete", url, kwargs))
        return DeleteResponse()

    monkeypatch.setattr("app.secops.github.settings.GITHUB_TOKEN", "gh-token")
    monkeypatch.setattr("app.secops.github.settings.GITHUB_DEFAULT_OWNER", "vaelqorix")
    monkeypatch.setattr("app.secops.github.settings.GITHUB_TOKEN_SECRET_NAMES", "PIPELINE_TOKEN")
    monkeypatch.setattr("app.secops.github.requests.get", fake_get)
    monkeypatch.setattr("app.secops.github.requests.put", fake_put)
    monkeypatch.setattr("app.secops.github.requests.delete", fake_delete)

    assert dispatch_github_command(
        command="devsecops.resolve_pipeline",
        payload={"target": "repository:vaelqorix/core"},
    )["status"] == "ok"
    assert dispatch_github_command(
        command="devsecops.block_deployment",
        payload={"target": "core", "pipeline": {"environment": "prod"}},
    )["operation"] == "environment_protection_gate"
    assert dispatch_github_command(
        command="devsecops.quarantine_artifact",
        payload={"target": "core", "finding": {"artifact_id": "123"}},
    )["artifact_id"] == "123"
    assert dispatch_github_command(
        command="devsecops.revoke_pipeline_token",
        payload={"target": "core"},
    )["secret_names"] == ["PIPELINE_TOKEN"]
    assert calls
    with pytest.raises(RuntimeError):
        dispatch_github_command(command="unsupported", payload={})


@pytest.mark.asyncio
async def test_monitoring_health_runtime_compliance_and_correlation(monkeypatch, db_session):
    import app.routers.monitoring_health as monitoring_health
    from app.compliance.router import read_compliance_evidence

    class FakeOkResponse:
        status_code = 200

    class FakeDownResponse:
        status_code = 503

    class OkClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url):
            return FakeOkResponse()

    class DownClient(OkClient):
        async def get(self, url):
            return FakeDownResponse()

    monkeypatch.setattr(monitoring_health.httpx, "AsyncClient", lambda *a, **kw: OkClient())
    assert (await health_full(db_session))["overall"] == "up"
    monkeypatch.setattr(monitoring_health.httpx, "AsyncClient", lambda *a, **kw: DownClient())
    degraded = await health_full(db_session)
    assert degraded["database"] == "up"
    assert degraded["overall"] == "degraded"

    status = runtime_status()
    enqueued = enqueue_playbook(EnqueueRequest(payload={"playbook": "contain"}, idempotency_key="pb-1"))
    duplicate = enqueue_playbook(EnqueueRequest(payload={"playbook": "contain"}, idempotency_key="pb-1"))
    from app.runtime.router import PLAYBOOK_QUEUE

    old_max_size = PLAYBOOK_QUEUE.max_size
    PLAYBOOK_QUEUE.max_size = len(PLAYBOOK_QUEUE.items)
    backpressure = enqueue_playbook(EnqueueRequest(payload={"playbook": "overflow"}))
    PLAYBOOK_QUEUE.max_size = old_max_size
    compliance = read_compliance_evidence()

    monkeypatch.setattr(
        "app.routers.monitoring_correlation.correlation_engine.run_correlation",
        lambda db: {
            "created_count": 1,
            "created_threats": [],
            "rules_triggered": ["rule-a"],
            "fired_alerts": [],
            "timestamp": "now",
            "updated_count": 0,
            "resolved_count": 0,
        },
    )
    corr = run_correlation(db_session)

    assert status["schema"] == "vaelqorix.runtime.distributed.v1"
    assert enqueued["status"] in {"queued", "duplicate"}
    assert duplicate["status"] == "queued"
    assert duplicate["job"]["idempotency_key"] == "pb-1"
    assert backpressure["status"] == "backpressure"
    assert compliance["schema"] == "vaelqorix.compliance.evidence.v1"
    assert serialize_threat(object())["id"] is None
    assert corr["created_count"] == 1


def test_redqueen_scoring_ueba_policy_and_training_edges(db_session):
    scored = score_perception(
        {
            "level": "critical",
            "category": "database",
            "source_ip": "203.0.113.7",
            "database_name": "payments",
            "metadata": {
                "status": "open",
                "occurrences": "bad",
                "behavior": {
                    "failed_logins": "12",
                    "distinct_source_ips": "6",
                    "geo_velocity_kmh": "1200",
                    "new_country": True,
                    "off_hours": True,
                    "privileged_account": True,
                    "bytes_out": "700000000",
                },
            },
            "labels": {"severity": "critical"},
            "siem": {"state": "firing", "active_minutes": "bad"},
            "mcp_context": {
                "critical_dependency": True,
                "business_criticality": "tier0",
                "asset_tier": "prod",
                "blast_radius": "enterprise",
                "exposed_to_internet": True,
                "active_incident_count": "bad",
            },
            "ueba": {"anomaly_score": "bad", "signals": ["ueba:privileged_account"]},
            "title": "Credential stuffing with lateral movement and ransomware",
        }
    )
    explicit_bad = score_perception({"score": "bad"})
    ueba = analyze_ueba_signals(
        {
            "metadata": {"endpoint": {"process_anomaly": True}},
            "description": "impossible travel and password spray",
            "siem": {"value": "bad"},
        }
    )
    invalid_policy = evaluate_policy("bad", "observe")
    unknown_policy = evaluate_policy(50, "unknown")
    human_policy = evaluate_policy(90, "network_isolate")

    db_session.add_all(
        [
            Verdict(
                verdict_id="train-high-fail-1",
                target="srv",
                action_type="network_isolate",
                confidence=0.9,
                factors='["lateral_movement"]',
                execution_controls=json.dumps(
                    {
                        "llm_governance": {
                            "approved_for_ares": False,
                            "present_guardrails": ["schema_validation"],
                        },
                        "llm_contract": {"final_action_source": "guardrail"},
                    }
                ),
            ),
            Verdict(
                verdict_id="train-high-fail-2",
                target="srv",
                action_type="network_isolate",
                confidence=0.95,
                factors='["credential_stuffing"]',
                execution_controls="{}",
            ),
            ExecutionResult(
                verdict_id="train-high-fail-1",
                ares_id="ares",
                status="failed",
                action_type="network_isolate",
                target_entity="srv",
                result_hash="hash-a",
            ),
            ExecutionResult(
                verdict_id="train-high-fail-2",
                ares_id="ares",
                status="failed",
                action_type="network_isolate",
                target_entity="srv",
            ),
        ]
    )
    db_session.commit()
    report = build_training_report(db_session, limit=10)

    assert scored["risk_score"] == 100
    assert explicit_bad["risk_score"] == 0
    assert "ueba:impossible_travel_text" in ueba["signals"]
    assert invalid_policy["code"] == "score_out_of_range"
    assert unknown_policy["code"] == "action_unknown"
    assert human_policy["code"] == "human_required"
    assert "recalibrate_high_confidence_threshold" in report["recommendations"]
    assert report["ai_governance"]["missing_governance_count"] >= 1


def test_ares_planner_firewall_approval_memory_monitor_and_kill_switch(monkeypatch, db_session):
    actions = [
        "network_isolate",
        "identity_lockdown",
        "require_mfa",
        "revoke_session",
        "degrade_privileges",
        "endpoint_isolate",
        "soar_delegate",
        "system_harden",
        "aggressive_containment",
        "crypto_rotate",
        "require_release_approval",
        "revoke_pipeline_token",
        "quarantine_artifact",
        "block_deployment",
        "observe",
    ]
    plans = [build_plan({"action_type": action, "target": "asset", "risk_score": 80}) for action in actions]
    bridge_trace = {
        "block_targets": [
            {"type": "network_indicator", "value": "203.0.113.10", "action": "block"},
            {"type": "identity", "value": "user:alice", "action": "revoke"},
            {"type": "device", "value": "host-1", "action": "isolate"},
            {"type": "repository", "value": "repo", "action": "freeze"},
            {"type": "asn", "value": "AS64500", "action": "block"},
            {"type": "unknown", "value": "x", "action": "review"},
            {"type": "domain", "value": "", "action": "ignore"},
            "bad",
        ]
    }
    containment = build_aggressive_containment(
        verdict={"target": "asset", "action_type": "aggressive_containment", "risk_score": 90},
        bridge_trace=bridge_trace,
        controls={"change_ticket": "CHG-1"},
    )
    allowed = evaluate_internal_firewall(
        verdict={"execution_controls": {}},
        plan={"action_type": "observe", "target": "asset"},
        advisor_review={},
        controls={},
    )
    denied = evaluate_internal_firewall(
        verdict={"execution_controls": {}},
        plan={"action_type": "block_deployment", "target": "prod-db"},
        advisor_review={},
        controls={"firewall_policy": {"deny_actions": ["block_deployment"]}},
    )
    protected = evaluate_internal_firewall(
        verdict={"execution_controls": {}},
        plan={"action_type": "network_isolate", "target": "prod-db"},
        advisor_review={},
        controls={"firewall_policy": {"protected_targets": ["prod-*"]}},
    )
    advisor_denied = evaluate_internal_firewall(
        verdict={"execution_controls": {}},
        plan={"action_type": "network_isolate", "target": "asset"},
        advisor_review={"safe_to_execute": False},
        controls={"enforce_advisor_firewall": True},
    )
    verdict = {
        "verdict_id": "approval-edge",
        "target": "asset",
        "action_type": "network_isolate",
        "risk_score": 90.0,
    }
    approval = build_approval_payload(verdict=verdict, approver="lead", reason="approved")
    bad_signature = dict(approval)
    bad_signature["signature"] = "bad"
    mismatch = dict(approval)
    mismatch["target"] = "other"
    mismatch["signature"] = sign_payload({k: v for k, v in mismatch.items() if k != "signature"})
    not_granted = dict(approval)
    not_granted["approved"] = False
    not_granted["signature"] = sign_payload({k: v for k, v in not_granted.items() if k != "signature"})
    no_approver = dict(approval)
    no_approver["approver"] = ""
    no_approver["signature"] = sign_payload({k: v for k, v in no_approver.items() if k != "signature"})

    db_session.add(
        Verdict(
            verdict_id="memory-success",
            target="asset",
            action_type="observe",
            risk_score=10,
        )
    )
    db_session.add(
        ExecutionResult(
            verdict_id="memory-success",
            ares_id="ares",
            status="success",
            evidence="{bad-json",
            result_hash="hash-success",
        )
    )
    db_session.commit()
    memory = read_ares_memory(db_session, target="asset")
    empty_health = evaluate_ares_health({"count": 0, "failure_rate": 0, "consecutive_failures": 0})
    bad_health = evaluate_ares_health({"count": 3, "failure_rate": 0.8, "consecutive_failures": 3})

    class FakeRedisClient:
        def __init__(self):
            self.value = None

        def get(self, key):
            return self.value

        def set(self, key, value):
            self.value = value

    class FakeRedisModule:
        created = FakeRedisClient()

        class Redis:
            @staticmethod
            def from_url(*_args, **_kwargs):
                return FakeRedisModule.created

    monkeypatch.setattr("app.ares.kill_switch.redis", FakeRedisModule)
    monkeypatch.setattr("app.ares.kill_switch.settings.ARES_KILL_SWITCH_BACKEND", "redis")
    reset_kill_switch_store()
    store = RedisKillSwitchStore(url="redis://local", key_prefix="vx", key="kill")
    assert store.read()["enabled"] is True
    store.write({"enabled": False, "reason": "incident", "actor": "soc", "updated_at": "now"})
    assert store.read()["reason"] == "incident"
    set_ares_kill_switch(True, reason="incident", actor="soc")
    state = kill_switch_state()
    reset_kill_switch_store()

    assert len(plans) == len(actions)
    assert containment["activation"] == "immediate"
    assert allowed.allowed is True
    assert denied.code == "firewall_action_denied"
    assert protected.code == "firewall_protected_target_control_missing"
    assert advisor_denied.code == "advisor_marked_unsafe"
    assert verify_approval_payload(verdict=verdict, approval=None)["code"] == "approval_missing"
    assert verify_approval_payload(verdict=verdict, approval={"signature": ""})["code"] == (
        "approval_signature_missing"
    )
    assert verify_approval_payload(verdict=verdict, approval=bad_signature)["code"] == (
        "approval_signature_invalid"
    )
    assert verify_approval_payload(verdict=verdict, approval=mismatch)["code"] == (
        "approval_verdict_mismatch"
    )
    assert verify_approval_payload(verdict=verdict, approval=not_granted)["code"] == (
        "approval_not_granted"
    )
    assert verify_approval_payload(verdict=verdict, approval=no_approver)["code"] == (
        "approval_approver_missing"
    )
    assert verify_approval_payload(verdict=verdict, approval=approval)["valid"] is True
    assert memory["last_result_hash"] == "hash-success"
    assert empty_health["status"] == "unknown"
    assert bad_health["status"] == "critical"
    assert state["backend"] == "redis"


def test_runtime_logs_and_prometheus_client_edges(monkeypatch):
    tmp_path = Path(".test-data") / f"logs-{uuid4().hex}"
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        (log_dir / "app.log").write_text(
            "\n".join(
                [
                    "bad line",
                    "2026-08-16 10:00:00,000 - INFO - api - GET /monitoring/health -> 200 (12.5ms)",
                    "2026-08-16 10:01:00,000 - WARNING - hook - ALERT_HOOK ip=10.0.0.1 len=1",
                    "broken - INFO - api - bad timestamp",
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        logs = list_runtime_logs(limit=10, severity="all", search="monitoring")
        warning = _parse_log_line(
            "2026-08-16 10:01:00,000 - ERROR - api - POST /users/ -> 500 (1ms)",
            "app.log",
        )
    finally:
        rmtree(tmp_path, ignore_errors=True)

    class FakeResponse:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.RequestException("bad status")

    def fake_get(url, **kwargs):
        if url.endswith("/api/v1/query"):
            return FakeResponse({"status": "success", "data": {"result": [{"metric": {}}]}})
        return FakeResponse(
            {
                "status": "success",
                "data": {
                    "alerts": [
                        {"state": "firing", "labels": {"alertname": "A"}},
                        "bad",
                        {"state": "pending", "labels": {"alertname": "B"}},
                    ]
                },
            }
        )

    monkeypatch.setattr("app.services.prometheus_client.requests.get", fake_get)
    client = PrometheusClient(base_url="http://prometheus/")
    assert logs["total"] == 1
    assert warning["action"] == "FAILED"
    assert client.has_result("up") is True
    assert len(client.get_alerts(state=None)) == 2
    assert client.get_firing_alerts()[0]["state"] == "firing"
    assert PrometheusClient.build_fingerprint({"alertname": "A", "instance": "i", "job": "j"}, "svc") == (
        "A|i|j|svc"
    )


@pytest.mark.asyncio
async def test_main_worker_startup_admin_and_runtime_edges(monkeypatch):
    import app.main as main

    class FakeSession:
        closed = False

        def query(self, model):
            return self

        def first(self):
            return None

        def add(self, item):
            self.added = item

        def commit(self):
            self.committed = True

        def close(self):
            self.closed = True

    sleeps = {"count": 0}

    async def fake_sleep(_seconds):
        sleeps["count"] += 1
        if sleeps["count"] >= 2:
            raise asyncio.CancelledError()

    class FakeEngine:
        def run_correlation(self, db):
            return {"created_count": 0}

    monkeypatch.setattr(main.settings, "VAELQORIX_CORRELATION_STARTUP_DELAY_SEC", 0)
    monkeypatch.setattr(main.settings, "VAELQORIX_CORRELATION_INTERVAL_SEC", 5)
    monkeypatch.setattr(main, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(main, "correlation_engine", FakeEngine())
    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await main.correlation_worker()

    monkeypatch.setattr(main.settings, "ENV", "production")
    assert main.create_default_admin_dev() is None

    session = FakeSession()
    monkeypatch.setattr(main.settings, "ENV", "development")
    monkeypatch.setattr(main.settings, "BOOTSTRAP_ADMIN_PASSWORD", None)
    monkeypatch.setattr(main, "SessionLocal", lambda: session)
    assert main.create_default_admin_dev() is None
    assert session.closed is True

    session_created = FakeSession()
    monkeypatch.setattr(main.settings, "BOOTSTRAP_ADMIN_PASSWORD", "strong-password")
    monkeypatch.setattr(main.settings, "BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setattr(main, "SessionLocal", lambda: session_created)
    assert main.create_default_admin_dev() is None
    assert getattr(session_created, "committed", False) is True

    class FailingSession(FakeSession):
        def first(self):
            raise RuntimeError("db init failed")

    failing = FailingSession()
    monkeypatch.setattr(main, "SessionLocal", lambda: failing)
    assert main.create_default_admin_dev() is None
    assert failing.closed is True

    class ReadyDb:
        def execute(self, query):
            return object()

    class DownDb:
        def execute(self, query):
            raise RuntimeError("down")

    assert main.root().status_code == 307
    assert main.favicon().status_code == 204
    assert main.health()["status"] == "ok"
    assert main.ready(ReadyDb()) == {"status": "ready"}
    assert main.ready(DownDb()).status_code == 503
    monkeypatch.setattr(main.settings, "ENV", "production")
    with pytest.raises(HTTPException):
        main.debug_config(current_admin=object())


def test_entra_graph_dispatcher_real_command_paths(monkeypatch):
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_TENANT_ID", "tenant")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_CLIENT_ID", "client")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_CLIENT_SECRET", "secret")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_GRAPH_BASE_URL", "https://graph.example/v1.0")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_GRAPH_TOKEN_URL", "")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_GRAPH_SCOPE", "")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_REQUIRE_MFA_POLICY_URL", "https://policy.example/mfa")
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS", "g1,g2")

    class FakeResponse:
        def __init__(self, payload=None, status_code=200):
            self._payload = payload or {}
            self.status_code = status_code
            self.headers = {"request-id": "REQ-ENTRA"}

        def json(self):
            return self._payload

        def raise_for_status(self):
            return None

    calls = []

    def fake_post(url, **kwargs):
        calls.append(("post", url, kwargs))
        if "oauth2" in url:
            return FakeResponse({"access_token": "token"})
        return FakeResponse(status_code=202)

    def fake_get(url, **kwargs):
        calls.append(("get", url, kwargs))
        return FakeResponse(
            {
                "id": "graph-user-id",
                "userPrincipalName": "alice@corp.com",
                "accountEnabled": True,
            }
        )

    def fake_patch(url, **kwargs):
        calls.append(("patch", url, kwargs))
        return FakeResponse(status_code=204)

    def fake_delete(url, **kwargs):
        calls.append(("delete", url, kwargs))
        return FakeResponse(status_code=204)

    monkeypatch.setattr("app.identity.entra_graph.requests.post", fake_post)
    monkeypatch.setattr("app.identity.entra_graph.requests.get", fake_get)
    monkeypatch.setattr("app.identity.entra_graph.requests.patch", fake_patch)
    monkeypatch.setattr("app.identity.entra_graph.requests.delete", fake_delete)

    assert dispatch_entra_graph_command(
        command="identity.resolve",
        payload={"target": "user:alice@corp.com"},
    )["graph_user_id"] == "graph-user-id"
    assert dispatch_entra_graph_command(
        command="identity.disable_credentials",
        payload={"target": "alice@corp.com"},
    )["operation"] == "accountEnabled=false"
    assert dispatch_entra_graph_command(
        command="identity.revoke_sessions",
        payload={"target": "alice@corp.com"},
    )["operation"] == "revokeSignInSessions"
    assert dispatch_entra_graph_command(
        command="identity.require_mfa",
        payload={"target": "alice@corp.com"},
    )["mode"] == "entra_graph_policy_bridge"
    degraded = dispatch_entra_graph_command(
        command="identity.degrade_privileges",
        payload={"target": "alice@corp.com"},
    )

    assert degraded["group_ids"] == ["g1", "g2"]
    assert calls
    with pytest.raises(RuntimeError):
        dispatch_entra_graph_command(command="unsupported", payload={"target": "alice"})
    monkeypatch.setattr("app.identity.entra_graph.settings.ENTRA_CLIENT_SECRET", "")
    with pytest.raises(RuntimeError):
        dispatch_entra_graph_command(command="identity.resolve", payload={"target": "alice"})


def test_settings_production_validators_and_loopback_aliases():
    base = {
        "ENV": "production",
        "SECRET_KEY": "strong-secret-value",
        "VAELQORIX_MONITOR_TOKEN": "monitor",
        "SECRET_BACKEND": "file",
        "VAELQORIX_PUBLIC_REGISTRATION_ENABLED": False,
        "RATE_LIMIT_BACKEND": "redis",
        "REPLAY_GUARD_BACKEND": "redis",
        "ARES_KILL_SWITCH_BACKEND": "redis",
        "ACTION_EXECUTION_MODE": "webhook",
        "AI_PROVIDER": "azure_openai",
        "VECTOR_STORE_PROVIDER": "qdrant",
    }

    assert Settings(**base).ENV == "production"
    failure_cases = [
        {"SECRET_KEY": "change-me"},
        {"VAELQORIX_MONITOR_TOKEN": None},
        {"SECRET_BACKEND": "env"},
        {"VAELQORIX_PUBLIC_REGISTRATION_ENABLED": True},
        {"RATE_LIMIT_BACKEND": "in_memory"},
        {"REPLAY_GUARD_BACKEND": "in_memory"},
        {"ARES_KILL_SWITCH_BACKEND": "in_memory"},
        {"ACTION_EXECUTION_MODE": "mock"},
        {"AI_PROVIDER": "local_stub"},
        {"VECTOR_STORE_PROVIDER": "local"},
    ]
    for override in failure_cases:
        config = {**base, **override}
        with pytest.raises(ValueError):
            Settings(**config)

    assert _prefer_ipv4_loopback("http://localhost:9090") == "http://127.0.0.1:9090"
    assert _prefer_ipv4_loopback(None) is None
    assert _prefer_ipv4_loopback("https://example.com") == "https://example.com"


@pytest.mark.asyncio
async def test_monitoring_response_logs_host_summary_and_alertmanager_errors(monkeypatch, db_session):
    import app.routers.monitoring as monitoring

    db_session.add_all(
        [
            ResponseLog(
                source="alertmanager",
                source_ip="127.0.0.1",
                payload_hash="hash-a",
                payload_size=10,
                alert_count=1,
                status="received",
                sample="{}",
            ),
            ResponseLog(
                source="other",
                source_ip="127.0.0.2",
                payload_hash="hash-b",
                payload_size=11,
                alert_count=2,
                status="failed",
                sample="{}",
            ),
        ]
    )
    db_session.commit()
    filtered = monitoring.get_response_logs(
        limit=100,
        source="alertmanager",
        status="received",
        db=db_session,
    )
    assert len(filtered) == 1

    async def fake_first(candidates):
        query = candidates[0]
        return {"available": True, "value": 10.0, "query": query, "errors": []}

    async def fake_nics():
        return {"data": [{"name": "Ethernet0", "bytes_total": 100}], "count": 1}

    async def fake_gpu():
        return {"available": False, "items": []}

    monkeypatch.setattr(monitoring, "_first_prometheus_scalar", fake_first)
    monkeypatch.setattr(monitoring, "list_windows_nics", fake_nics)
    monkeypatch.setattr(monitoring, "gpu_summary", fake_gpu)
    summary = await monitoring.host_summary()
    assert summary["network_mbps"]["nic"] == "Ethernet0"

    class BadJsonRequest:
        client = type("Client", (), {"host": "127.0.0.1"})()

        async def json(self):
            raise RuntimeError("bad json")

    with pytest.raises(HTTPException):
        await monitoring.alertmanager_hook(BadJsonRequest(), db_session)

    class BadHashRequest:
        client = type("Client", (), {"host": "127.0.0.1"})()

        async def json(self):
            return {"bad": object()}

    with pytest.raises(HTTPException):
        await monitoring.alertmanager_hook(BadHashRequest(), db_session)

    class BadDb:
        def add(self, item):
            return None

        def commit(self):
            raise RuntimeError("db down")

        def rollback(self):
            self.rolled_back = True

    class GoodRequest:
        client = None

        async def json(self):
            return [{"labels": {"alertname": "A"}}]

    with pytest.raises(HTTPException):
        await monitoring.alertmanager_hook(GoodRequest(), BadDb())


def test_vector_store_wazuh_and_prometheus_error_edges(monkeypatch):
    assert embed_text("", dimensions=3) == [0.0, 0.0, 0.0]
    assert cosine_similarity([], [1.0]) == 0.0
    assert cosine_similarity([0.0], [1.0]) == 0.0
    store = LocalVectorStore()
    store.upsert(collection="c", record_id="r1", text="alpha beta")
    results = store.search(collection="c", query="alpha", limit=100)
    assert results[0]["id"] == "r1"
    assert store.delete_collection("c") is True
    assert store.delete_collection("c") is False

    assert adapt_wazuh_event({"rule": {"level": 13, "id": "100"}, "agent": {"name": "h"}})[
        "severity"
    ] == "critical"
    assert adapt_wazuh_event({"severity": 9})["severity"] == "high"
    assert adapt_wazuh_event({"severity": 4})["severity"] == "medium"
    assert adapt_wazuh_event({"severity": 1})["severity"] == "low"
    assert adapt_wazuh_event({"severity": "custom"})["severity"] == "custom"

    class BadResponse:
        def raise_for_status(self):
            raise requests.RequestException("down")

    class NonSuccessResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "error"}

    class BadAlertPayload(NonSuccessResponse):
        def json(self):
            return {"status": "success", "data": []}

    client = PrometheusClient(base_url="http://prom")
    monkeypatch.setattr("app.services.prometheus_client.requests.get", lambda *a, **k: BadResponse())
    assert client.query("up") == []
    assert client.get_alerts() == []
    monkeypatch.setattr(
        "app.services.prometheus_client.requests.get",
        lambda *a, **k: NonSuccessResponse(),
    )
    assert client.query("up") == []
    assert client.get_alerts() == []
    monkeypatch.setattr(
        "app.services.prometheus_client.requests.get",
        lambda *a, **k: BadAlertPayload(),
    )
    assert client.get_alerts() == []


def test_secops_router_private_edges_and_lifecycle_not_found(monkeypatch, db_session):
    from app.secops import router as secops_router_module

    event = ThreatEvent(
        source="devsecops:broken",
        event_id="broken-normalized",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        event_type="broken",
        severity=3,
        entity_id="repo:broken",
        entity_type="repository",
        mitre_tags="{bad-json",
        normalized="{bad-json",
        normalized_payload="{bad-json",
        raw_payload="{}",
        risk_score=10.0,
    )

    response = secops_router_module._event_response(event, duplicate=True, elapsed_ms=12.345)
    assert response["mitre_tags"] == []
    assert response["signals"] == []
    assert response["is_duplicate"] is True
    assert response["processing_time_ms"] == 12.35

    from app.core.settings import settings as runtime_settings

    monkeypatch.setattr(runtime_settings, "ENTERPRISE_TENANT_MODE", "strict")
    with pytest.raises(HTTPException) as forbidden:
        secops_router_module._reject_tenant_mismatch({"tenant_id": "tenant-a"}, "tenant-b")
    assert forbidden.value.status_code == 403
    secops_router_module._reject_tenant_mismatch({"tenant_id": "tenant-a"}, None)
    monkeypatch.setattr(runtime_settings, "ENTERPRISE_TENANT_MODE", "disabled")
    secops_router_module._reject_tenant_mismatch({"tenant_id": "tenant-a"}, "tenant-b")

    lifecycle_payload = secops_router_module.SecurityEventLifecycleRequest()
    assert secops_router_module.run_secops_security_event_lifecycle(
        "missing-source",
        lifecycle_payload,
        db_session,
        {},
    ) == {"status": "not_found", "source_event_id": "missing-source"}

    monkeypatch.setattr(
        secops_router_module,
        "persist_identity_pipeline_correlation_event",
        lambda *args, **kwargs: (
            None,
            False,
            {"correlated": False, "correlation_score": 0.0},
        ),
    )
    correlation_payload = secops_router_module.DevSecOpsCorrelationLifecycleRequest()
    assert secops_router_module.run_identity_pipeline_correlation_lifecycle(
        "nobody@example.com",
        correlation_payload,
        db=db_session,
        enterprise_context={},
    )["status"] == "not_correlated"


def test_ingestion_aresx_router_private_normalization_edges(db_session):
    from app.ingestion import aresx_router
    from app.ingestion.aresx_router import AresXIngestEventRequest

    normalized = {"category": "Privilege Escalation", "level": "critical", "fingerprint": "fp-1"}
    assert aresx_router._event_type(normalized, {}) == "privilege_escalation"
    assert aresx_router._event_id("custom", normalized, {}) == "fp-1"
    assert aresx_router._entity({}, {"username": "alice"}) == ("user:alice", "user")
    assert aresx_router._entity({}, {"agent": {"name": "node-1"}}) == ("host:node-1", "host")
    assert aresx_router._entity({"target_service": "10.0.0.9"}, {}) == (
        "network:10.0.0.9",
        "network",
    )
    assert aresx_router._entity({"target_service": "api"}, {}) == ("service:api", "service")
    assert aresx_router._mitre_tags({}, {"mitre_tags": "T1059,T1078"}) == ["T1059", "T1078"]

    response_event = ThreatEvent(
        id=777,
        source="custom",
        event_id="evt-response",
        ingested_at=datetime(2026, 1, 1),
        event_type="security_event",
        severity=5,
        entity_id="unknown:unknown",
        entity_type="unknown",
        mitre_tags='["T1059"]',
    )
    response = aresx_router._response(response_event, is_duplicate=True, elapsed_ms=1.234)
    assert response["aresx_id"] == 777
    assert response["mitre_tags"] == ["T1059"]
    assert response["processing_time_ms"] == 1.23

    accepted = aresx_router.ingest_event(
        AresXIngestEventRequest(
            source="custom/source",
            payload={"event_id": "custom-evt", "destination_ip": "203.0.113.7"},
        ),
        db_session,
    )
    duplicate = aresx_router.ingest_event(
        AresXIngestEventRequest(
            source="custom/source",
            payload={"event_id": "custom-evt", "destination_ip": "203.0.113.7"},
        ),
        db_session,
    )
    assert accepted["is_duplicate"] is False
    assert duplicate["is_duplicate"] is True


def test_provider_strongest_action_fallbacks_and_preflights():
    assert strongest_supported_identity_action("unknown-provider", 99) == "soar_delegate"
    assert strongest_supported_identity_action("entra", 95) in {
        "identity_lockdown",
        "revoke_session",
        "degrade_privileges",
        "require_mfa",
    }
    assert identity_action_preflight_payload("active_directory", "identity_lockdown", 80)[
        "adjusted"
    ] is True
    with pytest.raises(ValueError):
        validate_identity_command("entra", "not_supported")

    assert strongest_supported_devsecops_action("unknown-provider", 99) == "soar_delegate"
    assert strongest_supported_devsecops_action("github_actions", 95) in {
        "block_deployment",
        "quarantine_artifact",
        "revoke_pipeline_token",
        "require_release_approval",
    }
    assert devsecops_action_preflight_payload("sonarqube", "block_deployment")[
        "adjusted"
    ] is True
    with pytest.raises(ValueError):
        validate_devsecops_command("github_actions", "not_supported")


def test_redqueen_trainer_private_helpers_and_governance_recommendations(db_session):
    from app.redqueen import trainer

    assert trainer._json_list("{bad") == []
    assert trainer._json_list('"not-a-list"') == []
    assert trainer._json_list('["one", 2, ""]') == ["one", "2"]
    assert trainer._json_dict("{bad") == {}
    assert trainer._json_dict("[]") == {}
    assert trainer._confidence_bucket(0.9) == "high"
    assert trainer._confidence_bucket(0.7) == "medium"
    assert trainer._confidence_bucket(0.1) == "low"
    assert trainer._rate(0, 0) == 0.0

    now = datetime.now(UTC).replace(tzinfo=None)
    verdicts = [
        Verdict(
            verdict_id=f"trainer-extra-{index}",
            threat_event_id=f"threat-{index}",
            target="repo",
            action_type="block",
            confidence=0.9,
            severity="high",
            factors='["weak_signal"]',
            execution_controls=json.dumps(
                {
                    "llm_governance": {
                        "approved_for_ares": False,
                        "present_guardrails": ["human_gate"],
                    },
                    "llm_contract": {"final_action_source": "rules"},
                }
            ),
            timestamp=now,
        )
        for index in range(2)
    ]
    results = [
        ExecutionResult(
            verdict_id=verdict.verdict_id,
            ares_id=f"ares-trainer-{index}",
            action_type=verdict.action_type,
            target_entity=verdict.target,
            status="failed",
            duration_ms=1,
            pre_state="{}",
            post_state="{}",
            evidence="[]",
            rollback_payload="{}",
            result_hash="" if index == 0 else "hash",
            timestamp=now,
        )
        for index, verdict in enumerate(verdicts)
    ]
    db_session.add_all([*verdicts, *results])
    db_session.commit()

    report = build_training_report(db_session, limit=500)
    assert "recalibrate_high_confidence_threshold" in report["recommendations"]
    assert "inspect_failure_factor:weak_signal" in report["recommendations"]


@pytest.mark.asyncio
async def test_health_full_database_down_and_component_down(monkeypatch):
    from app.routers import monitoring_health

    class BadDb:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("db down")

    class FakeResponse:
        status_code = 503

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, _url):
            return FakeResponse()

    monkeypatch.setattr(monitoring_health.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())

    result = await health_full(BadDb())
    assert result["database"] == "down"
    assert result["prometheus"] == "down"
    assert result["overall"] == "down"


def test_k8s_sensor_role_and_secret_findings():
    role = collect_k8s_findings(
        {"verb": "patch", "resource": "rolebindings", "namespace": "prod", "user": "admin"}
    )
    secret = collect_k8s_findings(
        {"verb": "create", "resource": "secrets", "namespace": "prod", "user": "svc"}
    )
    assert role[0].signals == ["privilege_escalation"]
    assert role[0].mitre_tags == ["T1098"]
    assert secret[0].signals == ["cloud_control_plane_change"]
    assert secret[0].mitre_tags == ["T1552"]


def test_identity_entra_redqueen_small_branches(monkeypatch, db_session):
    from app.identity.contracts import IdentitySignal
    from app.redqueen import bridge_trace, decision_engine

    signal = IdentitySignal(
        provider="entra",
        event_id="identity-extra",
        event_type="credential_attack",
        identity_id="admin@corp.com",
        severity=6,
        ip_address="198.51.100.7",
        geo_country="ES",
        geo_city="Madrid",
        device_id="device-1",
        mfa_present=True,
        privileged=True,
        impossible_travel=True,
        token_reuse=True,
    )
    event, _duplicate = persist_identity_event(db_session, signal)
    summary = summarize_identity_activity(db_session, entity_id=event.entity_id)
    assert "impossible_travel" in summary["signals"]
    assert "mfa_present" in summary["signals"]
    assert summary["risk_level"] in {"high", "critical"}

    normalized = normalize_entra_risk_event(
        {
            "id": "entra-invalid-date",
            "riskEventType": "impossibleTravel",
            "userPrincipalName": "admin@corp.com",
            "riskLevel": "high",
            "riskState": "active",
            "detectedDateTime": "not-a-date",
        }
    )
    assert normalized.occurred_at is None
    monkeypatch.setattr("app.identity.entra.get_secret", lambda *_args, **_kwargs: "secret")
    assert verify_entra_webhook_signature(b"{}", "signature", "not-a-number") is False
    monkeypatch.setattr("app.identity.entra.get_secret", lambda *_args, **_kwargs: "")
    assert verify_entra_webhook_signature(b"{}", None, None) is True

    assert decision_engine._fallback_action(30, domain="endpoint") == "observe"
    assert decision_engine._fallback_action(30, domain="network") == "observe"
    assert decision_engine._fallback_action(30, domain="devsecops") == "observe"
    assert decision_engine._fallback_action(51) == "soar_delegate"
    assert decision_engine._fallback_action(30) == "observe"
    assert decision_engine._enforce_min_action_by_score("network_isolate", 10) == "network_isolate"

    assert bridge_trace._ip_scope("not-an-ip") == "unknown"
    assert bridge_trace._ip_scope("224.0.0.1") == "non_routable"
    assert bridge_trace._ip_scope("8.8.8.8") == "public"
    candidates = bridge_trace._network_candidates({"dst_ip": "8.8.4.4"}, [])
    assert candidates[0]["role"] == "observed_destination"
    blocks = bridge_trace._block_targets([{"type": "ip", "value": ""}])
    assert blocks == []


def test_entra_graph_error_paths(monkeypatch):
    from app.identity import entra_graph

    with pytest.raises(RuntimeError, match="target user"):
        entra_graph._target_user_id("")

    class TokenResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {}

    class FailingResponse:
        status_code = 500

        def raise_for_status(self):
            raise RuntimeError("graph failed")

        def json(self):
            return {}

    config = entra_graph.EntraGraphConfig(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
        base_url="https://graph.example",
        token_url="https://login.example/token",
        scope="scope",
        timeout_sec=1.0,
    )
    monkeypatch.setattr(entra_graph.requests, "post", lambda *_args, **_kwargs: TokenResponse())
    with pytest.raises(RuntimeError, match="access_token"):
        entra_graph._access_token(config)

    monkeypatch.setattr(entra_graph, "_graph_config", lambda: config)
    monkeypatch.setattr(entra_graph, "_headers", lambda _config: {"Authorization": "Bearer token"})
    monkeypatch.setattr(entra_graph, "_configured_group_ids", lambda: [])
    with pytest.raises(RuntimeError, match="GROUP_IDS"):
        dispatch_entra_graph_command(
            command="identity.degrade_privileges",
            payload={"target": "user@example.com"},
        )

    monkeypatch.setattr(entra_graph, "_configured_group_ids", lambda: ["group-1"])
    monkeypatch.setattr(
        entra_graph,
        "_resolve_user",
        lambda *_args, **_kwargs: {
            "body": {},
            "path": "users/user@example.com",
            "status_code": 200,
            "provider_request_id": "",
        },
    )
    with pytest.raises(RuntimeError, match="user id"):
        dispatch_entra_graph_command(
            command="identity.degrade_privileges",
            payload={"target": "user@example.com"},
        )

    monkeypatch.setattr(
        entra_graph,
        "_resolve_user",
        lambda *_args, **_kwargs: {
            "body": {"id": "user-1"},
            "path": "users/user@example.com",
            "status_code": 200,
            "provider_request_id": "",
        },
    )
    monkeypatch.setattr(entra_graph.requests, "delete", lambda *_args, **_kwargs: FailingResponse())
    with pytest.raises(RuntimeError, match="graph failed"):
        dispatch_entra_graph_command(
            command="identity.degrade_privileges",
            payload={"target": "user@example.com"},
        )


def test_threat_router_not_found_and_pagination(monkeypatch, db_session):
    from app.routers import threats as threats_router

    listed = threats_router.list_threats(
        page=2,
        limit=5,
        source=None,
        active=None,
        fingerprint=None,
        title=None,
        sort="updated_at",
        order="desc",
        db=db_session,
    )
    assert isinstance(listed, list)

    with pytest.raises(HTTPException) as missing_read:
        threats_router.get_threat("missing-threat", db_session)
    assert missing_read.value.status_code == 404

    with pytest.raises(HTTPException) as missing_update:
        threats_router.update_threat("missing-threat", {}, db_session)
    assert missing_update.value.status_code == 404

    with pytest.raises(HTTPException) as missing_delete:
        threats_router.delete_threat("missing-threat", db_session)
    assert missing_delete.value.status_code == 404


def test_autonomy_service_generic_rag_and_nested_firewall_rejection(monkeypatch, db_session):
    from app.services import autonomy_service as autonomy_module

    assert AutonomyService._rag_domain({"source": "custom", "entity_type": "service"}) == "generic"

    event = ThreatEvent(
        source="devsecops:extra",
        event_id="autonomy-extra-event",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        event_type="pipeline_alert",
        severity=8,
        entity_id="repository:extra",
        entity_type="repository",
        mitre_tags='["T1078"]',
        raw_payload="{}",
        normalized_payload=json.dumps(
            {
                "identity_context": {
                    "subject": {"provider": "entra", "privileged": True},
                    "session": {"ip_address": "198.51.100.9", "device_id": "device-9"},
                    "geo": {"country": "ES"},
                    "signals": ["token_reuse"],
                },
                "devsecops_context": {
                    "pipeline": {
                        "provider": "github_actions",
                        "repository": "org/repo",
                        "environment": "prod",
                        "pipeline_id": "pipe-1",
                        "artifact": "image:sha",
                    }
                },
            }
        ),
        risk_score=85.0,
    )
    perception = AutonomyService._threat_event_perception(event, db_session)
    assert "identity_session:device_present" in perception["factors"]
    assert "devsecops_artifact:image:sha" in perception["factors"]

    class Decision:
        allowed = False
        code = "blocked_by_test"
        detail = "blocked"
        severity = "high"
        evidence = {"reason": "test"}

    monkeypatch.setattr(autonomy_module, "evaluate_internal_firewall", lambda **_kwargs: Decision())
    monkeypatch.setattr(autonomy_module, "execute_plan", lambda *_args, **_kwargs: {"status": "success"})
    monkeypatch.setattr(
        autonomy_module,
        "validate_verdict",
        lambda _verdict: type("Validation", (), {"valid": True, "code": "", "detail": ""})(),
    )

    verdict = {
        "verdict_id": "autonomy-firewall-nested",
        "timestamp": datetime.now(UTC).isoformat(),
        "threat_event_id": "autonomy-extra-event",
        "status": "approved",
        "target": "srv",
        "action_type": "network_isolate",
        "recommended_actions": ["network_isolate"],
        "primary_action": "network_isolate",
        "risk_score": 92.0,
        "confidence": 0.9,
        "confidence_score": 0.9,
        "factors": ["test"],
        "xai_explanation": {},
        "justification_xai": "test",
        "policy_check": True,
        "requires_human": False,
        "requires_human_approval": False,
        "policy_rule": "test",
        "ttl_seconds": 3600,
        "execution_controls": {
            "dry_run": True,
            "redqueen_attack_anticipation": {"predicted": True},
            "redqueen_bridge_trace": {"source": "198.51.100.9"},
            "redqueen_strategic_anticipation": {"scenario": "intrusion"},
        },
    }
    result = AutonomyService.execute_verdict(db_session, verdict=verdict, human_approved=True)
    assert result["status"] == "rejected"
    assert result["code"] == "blocked_by_test"


def test_provider_thresholds_runtime_logs_blacknode_and_kill_switch(monkeypatch):
    from app.ares import kill_switch as kill_switch_module
    from app.ares.kill_switch import InMemoryKillSwitchStore, RedisKillSwitchStore
    from app.identity import providers as identity_providers
    from app.platform import blacknode as blacknode_module
    from app.platform.blacknode import BlackNodeSecurityGateway, classify_action_risk
    from app.secops import providers as secops_providers

    assert validate_identity_action("entra", "unknown_action").provider == "entra"
    assert strongest_supported_identity_action("entra", 65) == "degrade_privileges"
    assert strongest_supported_identity_action("entra", 45) == "require_mfa"
    assert strongest_supported_identity_action("entra", 10) == "observe"
    original_identity = identity_providers.PROVIDER_CAPABILITIES["limited_test"] = (
        identity_providers.IdentityProviderCapabilities(
            "limited_test",
            frozenset({"identity.resolve"}),
        )
    )
    try:
        assert strongest_supported_identity_action("limited_test", 95) == "soar_delegate"
    finally:
        assert original_identity.provider == "limited_test"
        identity_providers.PROVIDER_CAPABILITIES.pop("limited_test", None)

    assert validate_devsecops_action("github_actions", "unknown_action").provider == (
        "github_actions"
    )
    assert strongest_supported_devsecops_action("github_actions", 85) == "quarantine_artifact"
    assert strongest_supported_devsecops_action("github_actions", 70) == "revoke_pipeline_token"
    assert strongest_supported_devsecops_action("github_actions", 50) == "require_release_approval"
    assert strongest_supported_devsecops_action("github_actions", 10) == "observe"
    secops_providers.PROVIDER_CAPABILITIES["limited_test"] = (
        secops_providers.DevSecOpsProviderCapabilities(
            "limited_test",
            frozenset({"devsecops.resolve_pipeline"}),
        )
    )
    try:
        assert strongest_supported_devsecops_action("limited_test", 95) == "soar_delegate"
    finally:
        secops_providers.PROVIDER_CAPABILITIES.pop("limited_test", None)

    parsed = _parse_log_line(
        "2026-99-99 99:99:99,999 - WARNING - vaelqorix - warning suspicious 10.0.0.1 10.0.0.2",
        source_file="app.log",
    )
    assert parsed["action"] == "FLAGGED"
    assert parsed["severity"] == "high"
    medium = _parse_log_line(
        "2026-01-01 10:00:00,123 - DEBUG - vaelqorix - custom diagnostic",
        source_file="app.log",
    )
    assert medium["severity"] == "medium"

    blacknode_module.DESTRUCTIVE_ACTIONS.add("wipe_disk")
    try:
        assert classify_action_risk("wipe_disk", 10) == "destructive"
    finally:
        blacknode_module.DESTRUCTIVE_ACTIONS.discard("wipe_disk")
    gateway = BlackNodeSecurityGateway()
    assert gateway.validate_verdict({"action_type": "network_isolate"}).code == (
        "signature_missing"
    )
    monkeypatch.setattr("app.platform.blacknode.verify_payload_signature", lambda *_args: False)
    assert gateway.validate_verdict(
        {"action_type": "network_isolate", "risk_score": 90, "signature": "bad"}
    ).code == "signature_invalid"
    monkeypatch.setattr("app.platform.blacknode.verify_payload_signature", lambda *_args: True)
    monkeypatch.setattr(
        "app.platform.blacknode.evaluate_policy",
        lambda *_args, **_kwargs: {"allowed": False, "rule": "deny"},
    )
    assert gateway.validate_verdict(
        {"action_type": "network_isolate", "risk_score": 90, "signature": "ok"}
    ).code == "policy_denied"
    monkeypatch.setattr(
        "app.platform.blacknode.evaluate_policy",
        lambda *_args, **_kwargs: {"allowed": True},
    )
    assert gateway.validate_verdict(
        {
            "action_type": "block_deployment",
            "risk_score": 90,
            "signature": "ok",
            "execution_controls": {"devsecops_provider": "sonarqube"},
        }
    ).code == "devsecops_provider_unsupported_action"

    local_store = InMemoryKillSwitchStore()
    local_store.write({"enabled": False, "reason": "test"})
    local_store.reset()
    assert local_store.read()["enabled"] is True

    monkeypatch.setattr(kill_switch_module, "redis", None)
    with pytest.raises(RuntimeError):
        RedisKillSwitchStore(url="redis://localhost", key_prefix="x", key="state")


def test_intelligence_redqueen_and_user_service_remaining_edges(db_session):
    from app.intelligence import llm_contract
    from app.intelligence import repository as intelligence_repository
    from app.models.user import User
    from app.redqueen import causal, drift, perception
    from app.services.user_service import UserService

    class BaseRepo(intelligence_repository.KnowledgeRepository):
        provider = "base"

    base_repo = BaseRepo()
    with pytest.raises(NotImplementedError):
        base_repo.list_documents()
    with pytest.raises(NotImplementedError):
        base_repo.search(query="q", domain="generic", factors=[])
    assert intelligence_repository._json_tuple("{bad") == ()
    assert intelligence_repository._json_tuple('"not-list"') == ()
    assert intelligence_repository._json_dict("{bad") == {}

    contract = llm_contract.normalize_llm_decision(
        {"action_type": "not_allowed", "confidence": "bad", "factors": ["x"]},
        risk_score=70,
        domain="generic",
        allowed_actions={"observe"},
        domain_actions={"observe"},
        fallback_action="observe",
        minimum_action="observe",
        action_severity={"observe": 0},
        input_factors=["factor"],
    )
    assert contract["action_type"] == "observe"
    assert contract["fallback_reason"] == "action_not_allowed"
    monkeypatch_contract = llm_contract.normalize_llm_decision(
        {"action_type": "observe", "confidence": "bad", "factors": ["x"]},
        risk_score=80,
        domain="generic",
        allowed_actions={"observe"},
        domain_actions={"observe"},
        fallback_action="observe",
        minimum_action="observe",
        action_severity={"observe": 0},
        input_factors=[],
    )
    assert monkeypatch_contract["confidence"] == 0.8

    assert perception._enum_value(None) is None
    assert perception._parse_datetime("not-a-date") is None
    perceived = perception.build_threat_perception(
        type(
            "Threat",
            (),
            {
                "id": "perception-1",
                "siem_metadata": {
                    "first_seen_at": "2026-01-01T00:00:00",
                    "last_seen_at": "2026-01-01T00:05:00",
                },
                "updated_at": None,
                "target_service": "svc",
                "database_host": "",
                "source_ip": "",
                "title": "Threat",
                "description": "",
                "source": "test",
                "level": "medium",
                "category": "network",
                "score": 10,
                "fingerprint": "fp",
                "database_name": "",
            },
        )()
    )
    assert perceived["siem"]["active_minutes"] == 5

    assert drift._severity(16, 0.0) == "high"
    assert drift._severity(-16, 0.0) == "falling"
    original_latest_scores = drift.RiskRepository.latest_scores
    drift.RiskRepository.latest_scores = staticmethod(
        lambda *_args, **_kwargs: [
            type("Score", (), {"score_0_100": 90.0})(),
            type("Score", (), {"score_0_100": 80.0})(),
        ]
    )
    try:
        assert "drift:risk_drop" in drift.analyze_risk_drift(
            db_session,
            target="entity",
            current_score=60,
        )["signals"]
        assert drift.analyze_risk_drift(db_session, target="entity")["current_score"] == 90.0
    finally:
        drift.RiskRepository.latest_scores = original_latest_scores

    assert "observacion" in causal.build_causal_chain(
        target="svc",
        risk_score=10,
        action_type="observe",
    )[
        "impact"
    ]
    assert "MFA" in causal.build_causal_chain(
        target="svc",
        risk_score=80,
        action_type="require_mfa",
    )[
        "action_rationale"
    ]
    assert "pipeline" in causal.build_causal_chain(
        target="svc",
        risk_score=80,
        action_type="revoke_pipeline_token",
    )["action_rationale"]
    assert "artefacto" in causal.build_causal_chain(
        target="svc",
        risk_score=80,
        action_type="quarantine_artifact",
    )["action_rationale"]
    assert "SOAR" in causal.build_causal_chain(
        target="svc",
        risk_score=80,
        action_type="soar_delegate",
    )[
        "action_rationale"
    ]

    assert evaluate_policy(score=10, action_type="network_isolate")["code"] == (
        "risk_below_action_minimum"
    )
    from app.redqueen import policy_matrix as policy_matrix_module

    policy_matrix_module.ACTION_POLICIES["temporary_low_max"] = policy_matrix_module.ActionPolicy(
        0,
        50,
        50,
        severity=1,
    )
    try:
        assert evaluate_policy(score=95, action_type="temporary_low_max")["code"] == (
            "risk_above_action_maximum"
        )
    finally:
        policy_matrix_module.ACTION_POLICIES.pop("temporary_low_max", None)

    assert UserService.set_user_active(db_session, "999999", True) is None
    db_session.add_all(
        [
            User(
                full_name="Filter Admin",
                email="filter-admin@example.com",
                hashed_password="hash",
                role="admin",
                is_active=True,
            ),
            User(
                full_name="Filter Analyst",
                email="filter-analyst@example.com",
                hashed_password="hash",
                role="analyst",
                is_active=False,
            ),
        ]
    )
    db_session.commit()
    users = UserService.get_users_paginated(
        db_session,
        page=1,
        limit=10,
        role="admin",
        is_active=True,
        search="filter-admin",
    )
    assert any(user.email == "filter-admin@example.com" for user in users.items)


def test_audit_store_verification_failure_edges():

    class ScalarResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class FakeDb:
        def __init__(self, rows, previous=None):
            self.rows = rows
            self.previous = previous

        def scalar(self, *_args, **_kwargs):
            return self.previous

        def scalars(self, *_args, **_kwargs):
            return ScalarResult(self.rows)

    def record(**overrides):
        data = {
            "record_id": str(uuid4()),
            "verdict_id": "verdict",
            "sequence_number": 1,
            "event_type": "event",
            "hash_prev": "",
            "hash_self": "",
            "content_hash": "",
            "chain_hash": "bad-chain",
            "previous_chain_hash": "",
            "timestamp": datetime(2026, 1, 1),
            "actor": "system",
            "actor_role": "system",
            "tenant_id": "default",
            "capability": "",
            "request_id": "",
            "action": "action",
            "payload": "{}",
            "result": "{}",
        }
        data.update(overrides)
        return type("AuditRecordFake", (), data)()

    missing_sequence = verify_aresx_audit_chain(FakeDb([record(sequence_number=None)]))
    assert missing_sequence["reason"] == "missing_sequence_number"

    previous = record(sequence_number=10, chain_hash="previous")
    gap = verify_aresx_audit_chain(
        FakeDb([record(sequence_number=12, previous_chain_hash="previous")], previous=previous),
        from_sequence=11,
    )
    assert gap["reason"] == "sequence_gap"

    chain_mismatch = verify_aresx_audit_chain(FakeDb([record()]))
    assert chain_mismatch["reason"] == "chain_hash_mismatch"

    previous_hash_mismatch = verify_audit_chain(FakeDb([record(hash_prev="wrong")]))
    assert previous_hash_mismatch["reason"] == "previous_hash_mismatch"

    bad_result = record(result="{bad", hash_self="wrong")
    self_hash_mismatch = verify_audit_chain(FakeDb([bad_result]))
    assert self_hash_mismatch["reason"] == "self_hash_mismatch"


def test_aresx_secops_service_and_router_remaining_edges(monkeypatch, db_session):
    from app.ingestion import aresx_router
    from app.ingestion.aresx_router import AresXIngestEventRequest
    from app.secops import router as secops_router_module
    from app.secops import service as secops_service_module

    assert aresx_router._event_type({}, {}) == "security_event"
    assert len(aresx_router._event_id("custom", {}, {"payload": "x"})) == 32
    assert aresx_router._entity({}, {}) == ("unknown:unknown", "unknown")
    event, duplicate = aresx_router._persist_event(
        db_session,
        {
            "source": "custom",
            "event_id": "aware-event",
            "occurred_at": datetime.now(UTC),
            "event_type": "security_event",
            "severity": 5,
            "entity_id": "unknown:unknown",
            "entity_type": "unknown",
            "mitre_tags": [],
            "raw_payload": {},
            "normalized_payload": {},
            "src_ip": "",
            "dst_ip": "",
            "src_port": None,
            "dst_port": None,
            "geo_country": "",
            "geo_city": "",
        },
    )
    assert duplicate is False
    assert event.occurred_at.tzinfo is None

    monkeypatch.setattr(aresx_router, "_canonicalize", lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("x")))
    with pytest.raises(HTTPException) as bad_ingest:
        aresx_router.ingest_event(AresXIngestEventRequest(source="bad", payload={}), db_session)
    assert bad_ingest.value.status_code == 400

    assert secops_service_module._correlation_entity(
        {"identity_entity_id": "user:alice", "devsecops_summary": {"repositories": []}}
    ) == ("user:alice", "user")

    class ScalarResult:
        def all(self):
            return [
                type("Event", (), {"normalized_payload": "{bad", "normalized": ""})(),
                type(
                    "Event",
                    (),
                    {
                        "normalized_payload": json.dumps({"actor_identity": "actor@example.com"}),
                        "normalized": "",
                    },
                )(),
            ]

    class FakeDb:
        def scalars(self, *_args, **_kwargs):
            return ScalarResult()

    assert secops_service_module._recent_devsecops_actors(FakeDb()) == ["actor@example.com"]

    monkeypatch.setattr(secops_service_module, "_recent_devsecops_actors", lambda *_args, **_kwargs: ["a", "b"])
    monkeypatch.setattr(
        secops_service_module,
        "correlate_identity_devsecops",
        lambda _db, *, actor_identity, limit=100: {
            "correlated": True,
            "correlation_score": 20.0 if actor_identity == "a" else 95.0,
            "recommended_action": "observe",
        },
    )
    monkeypatch.setattr(
        secops_service_module,
        "persist_identity_pipeline_correlation_event",
        lambda *_args, **_kwargs: (None, False, {"correlation_score": 95.0}),
    )
    materialized = secops_service_module.materialize_identity_pipeline_correlations(
        db_session,
        min_score=60,
    )
    assert {item["status"] for item in materialized["items"]} == {"below_threshold"}
    assert materialized["skipped"] == 2

    existing_event = ThreatEvent(
        source="secops:integration_security_abuse",
        event_id="security-lifecycle-not-found-verdict",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        event_type="integration_security_abuse",
        severity=8,
        entity_id="integration:github:default",
        entity_type="integration",
        mitre_tags="[]",
        raw_payload="{}",
        normalized_payload="{}",
        risk_score=80.0,
    )
    db_session.add(existing_event)
    db_session.commit()
    monkeypatch.setattr(
        secops_router_module.AutonomyService,
        "issue_verdict_from_threat_event",
        lambda *_args, **_kwargs: {"status": "not_found"},
    )
    assert secops_router_module.run_secops_security_event_lifecycle(
        "security-lifecycle-not-found-verdict",
        secops_router_module.SecurityEventLifecycleRequest(),
        db_session,
        {},
    )["status"] == "not_found"
    readiness = secops_router_module.secops_provider_readiness("github_actions")
    assert readiness["integration"] == "github_actions"
    assert readiness["capabilities"]["provider"] == "github_actions"


def test_more_remaining_service_edges(monkeypatch, db_session):
    from app.secops import router as secops_router_module
    from app.secops import service as secops_service_module
    from app.services import autonomy_service as autonomy_module

    client = PrometheusClient(base_url="http://prom")
    monkeypatch.setattr(client, "query", lambda _expr: (_ for _ in ()).throw(RuntimeError("down")))
    assert client.has_result("up") is False

    secops_event, _duplicate = secops_service_module._persist_security_abuse_event(
        db_session,
        group_key=("default", "github_actions", "replay_detected", "198.51.100.10"),
        items=[
            {
                "timestamp": datetime.now(UTC),
                "status_code": 401,
                "record_id": "audit-1",
                "source_event_id": "source-1",
                "payload_sha256": "hash",
            }
        ],
    )
    assert secops_event.timestamp.tzinfo is None

    event = ThreatEvent(
        source="devsecops:github_actions",
        event_id="devsecops-lifecycle-not-found-verdict",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        event_type="pipeline_alert",
        severity=7,
        entity_id="repository:org/repo",
        entity_type="repository",
        mitre_tags="[]",
        raw_payload="{}",
        normalized_payload="{}",
        risk_score=70.0,
    )
    monkeypatch.setattr(secops_router_module, "persist_devsecops_signal", lambda *_args, **_kwargs: (event, False))
    monkeypatch.setattr(
        secops_router_module,
        "persist_identity_pipeline_correlation_event",
        lambda *_args, **_kwargs: (
            event,
            False,
            {"correlated": True, "correlation_score": 70.0},
        ),
    )
    monkeypatch.setattr(
        secops_router_module.AutonomyService,
        "issue_verdict_from_threat_event",
        lambda *_args, **_kwargs: {"status": "not_found"},
    )
    signal = DevSecOpsSignal(
        provider="github_actions",
        event_id="sig-not-found",
        event_type="pipeline_alert",
        repository="org/repo",
        severity=7,
    )
    assert secops_router_module.run_devsecops_lifecycle(
        secops_router_module.DevSecOpsLifecycleRequest(signal=signal),
        db_session,
        {},
    )["status"] == "not_found"
    assert secops_router_module.run_identity_pipeline_correlation_lifecycle(
        "actor@example.com",
        secops_router_module.DevSecOpsCorrelationLifecycleRequest(),
        db=db_session,
        enterprise_context={},
    )["status"] == "not_found"

    class Decision:
        allowed = False
        code = "blocked_by_test"
        detail = "blocked"
        severity = "high"
        evidence = {}

    monkeypatch.setattr(autonomy_module, "evaluate_internal_firewall", lambda **_kwargs: Decision())
    monkeypatch.setattr(
        autonomy_module,
        "validate_verdict",
        lambda _verdict: type("Validation", (), {"valid": True, "code": "", "detail": ""})(),
    )
    verdict = {
        "verdict_id": "autonomy-no-redqueen-controls",
        "timestamp": datetime.now(UTC).isoformat(),
        "threat_event_id": "event",
        "status": "approved",
        "target": "srv",
        "action_type": "network_isolate",
        "recommended_actions": ["network_isolate"],
        "primary_action": "network_isolate",
        "risk_score": 90.0,
        "confidence": 0.9,
        "confidence_score": 0.9,
        "factors": [],
        "xai_explanation": {},
        "justification_xai": "",
        "policy_check": True,
        "requires_human": False,
        "requires_human_approval": False,
        "policy_rule": "test",
        "ttl_seconds": 3600,
        "execution_controls": {"dry_run": True},
    }
    assert AutonomyService.execute_verdict(db_session, verdict=verdict, human_approved=True)[
        "status"
    ] == "rejected"


@pytest.mark.asyncio
async def test_final_main_monitoring_session_and_correlation_edges(monkeypatch, db_session):
    import app.main as main
    from app.db import session as db_session_module
    from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
    from app.routers import monitoring
    from app.services.correlation_engine import CorrelationEngine

    class ExistingSession:
        closed = False

        def query(self, model):
            return self

        def first(self):
            return object()

        def close(self):
            self.closed = True

    existing_session = ExistingSession()
    monkeypatch.setattr(main.settings, "ENV", "development")
    monkeypatch.setattr(main, "SessionLocal", lambda: existing_session)
    assert main.create_default_admin_dev() is None
    assert existing_session.closed is True

    sleeps = {"count": 0}

    async def fake_sleep(_seconds):
        sleeps["count"] += 1
        if sleeps["count"] >= 3:
            raise asyncio.CancelledError()

    monkeypatch.setattr(main.settings, "VAELQORIX_CORRELATION_STARTUP_DELAY_SEC", 0)
    monkeypatch.setattr(main.settings, "VAELQORIX_CORRELATION_INTERVAL_SEC", 1)
    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    await main.correlation_lock.acquire()
    try:
        await main.correlation_worker()
    finally:
        if main.correlation_lock.locked():
            main.correlation_lock.release()
    assert sleeps["count"] >= 3

    class ClosableSession:
        closed = False

        def close(self):
            self.closed = True

    closable = ClosableSession()
    monkeypatch.setattr(db_session_module, "SessionLocal", lambda: closable)
    generator = db_session_module.get_db()
    assert next(generator) is closable
    with pytest.raises(StopIteration):
        next(generator)
    assert closable.closed is True

    monkeypatch.setattr(monitoring.settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(monitoring.settings, "ACTION_EXECUTION_MODE", "webhook")
    monkeypatch.setattr(monitoring.settings, "ACTION_SHARED_TOKEN", "")
    monkeypatch.setattr(monitoring.settings, "ALERTMANAGER_ALLOWED_CIDRS", "")
    readiness = monitoring._production_readiness_report()
    assert readiness["status"] == "needs_attention"
    assert any("ACTION_SHARED_TOKEN" in item for item in readiness["warnings"])
    assert any("ALERTMANAGER_ALLOWED_CIDRS" in item for item in readiness["warnings"])

    async def fake_bad_scalar(_query):
        return [{"value": [1, "bad"]}]

    monkeypatch.setattr(monitoring, "_prometheus_query_result", fake_bad_scalar)
    assert (await monitoring.gpu_summary())["available"] is False

    async def fake_first_prometheus_scalar(_queries):
        return {"available": False, "value": None, "query": None}

    async def fake_nics():
        return {"data": [{"name": "fallback0", "bytes_total": 42.0}]}

    async def fake_gpu_summary():
        return {"available": False}

    monkeypatch.setattr(monitoring, "_first_prometheus_scalar", fake_first_prometheus_scalar)
    monkeypatch.setattr(monitoring, "list_windows_nics", fake_nics)
    monkeypatch.setattr(monitoring, "gpu_summary", fake_gpu_summary)
    assert (await monitoring.host_summary())["network_mbps"]["nic"] == "fallback0"
    monkeypatch.setattr(
        monitoring,
        "list_runtime_logs",
        lambda **kwargs: {"items": [], "limit": kwargs["limit"], "severity": kwargs["severity"]},
    )
    assert monitoring.get_runtime_logs(limit=5, severity="ERROR", search=None)["limit"] == 5

    now = datetime.now()
    threat = ThreatModel(
        title="existing",
        source="prometheus/correlation",
        description="existing",
        level=ThreatLevel.high,
        category=ThreatCategory.availability,
        score=80,
        target_service="svc",
        fingerprint="fp-existing",
        siem_metadata={"status": "open"},
        created_at=now,
    )

    class SimpleDb:
        def add(self, item):
            self.item = item

        def commit(self):
            self.committed = True

        def refresh(self, item):
            self.refreshed = item

    touched = CorrelationEngine._touch_existing(SimpleDb(), threat, now=now, extra_meta={})
    assert touched.siem_metadata["first_seen_at"] == now.isoformat()

    fresh = ThreatModel(
        title="fresh",
        source="prometheus/correlation",
        description="fresh",
        level=ThreatLevel.high,
        category=ThreatCategory.availability,
        score=80,
        target_service="svc",
        fingerprint="fp-fresh",
        siem_metadata={"status": "open", "last_seen_at": now.isoformat()},
        updated_at=now,
        created_at=now,
    )

    class Query:
        def filter(self, *_args):
            return self

        def all(self):
            return [fresh]

    class ResolveDb:
        def query(self, model):
            return Query()

    assert CorrelationEngine()._auto_resolve(ResolveDb(), active_fingerprints=set(), now=now) == 0


@pytest.mark.asyncio
async def test_final_small_module_edge_contracts(monkeypatch, db_session):
    import time

    from app.actions.devsecops import DevSecOpsAction
    from app.ares import evidence as ares_evidence
    from app.ares.advisor import _risk_from_plan, review_plan
    from app.ares.executor import execute_plan
    from app.ares.internal_firewall import evaluate_internal_firewall
    from app.ares.kill_switch import RedisKillSwitchStore
    from app.ares.memory import read_ares_memory
    from app.ares.monitor import evaluate_ares_health
    from app.ares.router import _json_loads as ares_json_loads
    from app.ares.router import list_executions, run_lifecycle_from_threat
    from app.cases.router import CaseCreateRequest, create_case_endpoint
    from app.code_intelligence import analyzer
    from app.connectors.registry import connector_preflight
    from app.core.ai_provider import AIProvider, SafeAIProvider
    from app.core.rate_limit import InMemoryRateLimitStore, RedisRateLimitStore
    from app.core.replay_guard import InMemoryReplayGuardStore, RedisReplayGuardStore
    from app.detection.correlation import correlate_detections
    from app.detection.router import DetectionEvaluateRequest, detection_status, evaluate_detection
    from app.ingestion.normalizer import normalize_event
    from app.ingestion.router import ingest_adapter_event, normalize_adapter_only
    from app.models.audit_record import AuditRecord
    from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
    from app.models.user import User
    from app.platform.vaelqorixflow import vaelqorixflow_engine
    from app.platform.vaelqorixvault import vaelqorixvault_retriever
    from app.playbooks.contracts import Playbook, PlaybookStep
    from app.playbooks.engine import build_execution_plan
    from app.redqueen import router as redqueen_router
    from app.redqueen.analytical_brain import build_analytical_profile
    from app.redqueen.anticipation import anticipate_attack_path
    from app.redqueen.memory import recall_threat_context
    from app.redqueen.strategic_anticipation import build_strategic_anticipation
    from app.redqueen.trainer import build_training_report
    from app.redqueen.ueba import analyze_ueba_signals
    from app.routers import audit as audit_router
    from app.routers import auth as auth_router
    from app.routers import threats as threats_router
    from app.routers import users as users_router
    from app.routers.monitoring_health import health_full as monitoring_health_full
    from app.secops import github as github_provider
    from app.secops.readiness import _status, _valid_url, build_secops_integration_readiness
    from app.secops.tenant_policies import _json_loads as tenant_json_loads
    from app.sensors.cloud_sensor.collector import collect_cloud_findings
    from app.sensors.endpoint_agent.collector import collect_endpoint_findings
    from app.sensors.k8s_sensor.collector import collect_k8s_findings
    from app.sensors.network_sensor.collector import collect_network_findings
    from app.services.prometheus_client import PrometheusClient
    from app.services.runtime_log_service import list_runtime_logs
    from app.services.threat_service import ThreatService

    monkeypatch.setattr("app.actions.devsecops.validate_devsecops_command", lambda *_args: None)
    monkeypatch.setattr(
        "app.actions.devsecops.dispatch_command",
        lambda **kwargs: {"command": kwargs["command"], "payload": kwargs["payload"]},
    )
    rollback = DevSecOpsAction().rollback_step(
        {
            "target": "repository:org/repo",
            "provider": "github_actions",
            "step": "block_deployment",
            "change_ticket": "CHG-1",
            "pipeline": {"repository": "org/repo"},
        }
    )
    assert rollback.status == "ok"

    assert ares_evidence._json_loads("", {"fallback": True}) == {"fallback": True}
    assert ares_evidence._json_loads("{bad", []) == []
    assert _risk_from_plan({"max_criticality": 0}) == "low"
    monkeypatch.setattr(
        "app.ares.advisor.ai_provider.complete",
        lambda *_args: '{"required_safeguards":"bad","safe_to_execute":true}',
    )
    advised = review_plan(
        verdict={"verdict_id": "v1", "target": "critical-db", "action_type": "network_isolate"},
        plan={"action_type": "network_isolate", "target": "critical-db", "max_criticality": 1},
        controls={"mcp_context": {"blocked_actions": ["network_isolate"]}},
    )
    assert "blocked_action_policy_review" in advised["required_safeguards"]
    assert execute_plan({"action_type": "observe", "steps": []})["executed_steps"][0]["step"] == "noop"
    assert evaluate_ares_health({"count": 3, "failure_rate": 0.1})["status"] == "degraded"
    assert evaluate_ares_health({"count": 3, "failure_rate": 0.0})["status"] == "healthy"
    assert read_ares_memory(db_session, target=" ")["count"] == 0
    assert ares_json_loads("{bad", []) == []
    assert evaluate_internal_firewall(
        verdict={"execution_controls": {"mcp_tool_policy": {"allowed": False}}},
        plan={"action_type": "observe", "target": "srv"},
        advisor_review={},
    ).code == "mcp_tool_denied"
    assert evaluate_internal_firewall(
        verdict={},
        plan={"action_type": "network_isolate", "target": "srv"},
        advisor_review={},
        controls={"firewall_policy": {"allowed_actions": ["observe"]}},
    ).code == "firewall_action_not_allowed"
    monkeypatch.setattr("app.ares.kill_switch.redis", None)
    with pytest.raises(RuntimeError):
        RedisKillSwitchStore(url="redis://localhost:6379/0", key_prefix="x", key="k")

    payload = create_case_endpoint(
        CaseCreateRequest(title="case", severity="high", description="desc", artifacts=[])
    )
    assert payload["case"]["status"] == "open"
    assert connector_preflight("missing-provider", action="x", target="srv")["code"] == "provider_unknown"
    with pytest.raises(NotImplementedError):
        AIProvider().complete("", "")
    monkeypatch.setattr("app.core.ai_provider.settings.AI_PROVIDER", "ollama")
    assert SafeAIProvider().provider.__class__.__name__ == "OllamaProvider"
    assert SafeAIProvider.parse_json("```json\n{bad\n```") == {}

    memory_store = InMemoryRateLimitStore({"k": __import__("collections").deque([0.0])})
    monkeypatch.setattr("app.core.rate_limit.time.monotonic", lambda: 10.0)
    assert memory_store.check(key="k", limit=1, window_seconds=1).allowed is True
    monkeypatch.setattr("app.core.rate_limit.redis", None)
    with pytest.raises(RuntimeError):
        RedisRateLimitStore(url="redis://localhost:6379/0", key_prefix="x")
    replay_store = InMemoryReplayGuardStore({"old": 0.0})
    monkeypatch.setattr("app.core.replay_guard.time.monotonic", lambda: 10.0)
    assert replay_store.check(key="new", ttl_seconds=1).accepted is True
    monkeypatch.setattr("app.core.replay_guard.redis", None)
    with pytest.raises(RuntimeError):
        RedisReplayGuardStore(url="redis://localhost:6379/0", key_prefix="x")

    assert normalize_event({"score": "bad"})["score"] == 62
    with pytest.raises(HTTPException):
        ingest_adapter_event("does-not-exist", {}, db_session)
    with pytest.raises(HTTPException):
        normalize_adapter_only("does-not-exist", {})
    assert correlate_detections([])["incident_count"] == 0
    assert detection_status()["rule_count"] >= 0
    assert evaluate_detection(DetectionEvaluateRequest(events=[]))["status"] == "ok"

    temp_root = Path(".pytest-workspace-tmp") / "code-analyzer"
    if temp_root.exists():
        rmtree(temp_root)
    temp_root.mkdir(parents=True)
    try:
        monkeypatch.setattr(analyzer, "BACKEND_ROOT", temp_root)
        (temp_root / "__pycache__").mkdir()
        (temp_root / "__pycache__" / "ignored.py").write_text("x = 1", encoding="utf-8")
        bad_file = temp_root / "bad.py"
        bad_file.write_text("def broken(:\n", encoding="utf-8")
        report = analyzer.build_code_architecture_report(include_private=True)
        assert report.risks[0].rule == "syntax_error"
    finally:
        rmtree(temp_root)

    assert vaelqorixflow_engine.preview_workflow({"target": "srv", "action_type": "observe"})["plan"]
    monkeypatch.setattr(
        "app.platform.vaelqorixvault.retrieve_defensive_context",
        lambda **kwargs: type(
            "Context",
            (),
            {"query": kwargs["query"], "domain": kwargs["domain"], "references": []},
        )(),
    )
    assert vaelqorixvault_retriever.retrieve(query="q", domain="d", factors=[])["references"] == []
    playbook = Playbook(
        playbook_id="pb",
        name="PB",
        version="1",
        description="",
        steps=[
            PlaybookStep(
                step_id="s1",
                connector="firewall",
                action="block",
                when={"contains": {"labels": "prod"}, "min": {"risk": "bad"}},
            )
        ],
    )
    assert build_execution_plan(playbook, context={"labels": ["prod"], "risk": "bad"})["skipped"]

    assert redqueen_router._json_loads("{bad", []) == []
    fake_scalars = type("Scalars", (), {"all": lambda self: []})()
    fake_db = type("Db", (), {"scalars": lambda self, query: fake_scalars})()
    assert redqueen_router.list_verdicts(status="approved", target="srv", db=fake_db)["count"] == 0
    assert build_analytical_profile(
        target="srv", risk_score=30, action_type="network_isolate", factors=[], controls={}
    )["contradiction_count"] == 1
    assert anticipate_attack_path(
        target="srv",
        risk_score=70,
        factors=[],
        controls={"mcp_context": {"exposed_to_internet": True}},
    )["latest_stage"] == "reconnaissance"
    assert build_strategic_anticipation(
        target="srv",
        risk_score=80,
        factors=[],
        anticipation={"attack_stages": ["initial_access"], "horizon": "early"},
        bridge_trace={},
    )["confidence"] >= 0
    class EmptyQuery:
        def order_by(self, *_args):
            return self

        def limit(self, *_args):
            return self

        def all(self):
            return []

    training_db = type("TrainingDb", (), {"query": lambda self, model: EmptyQuery()})()
    assert build_training_report(training_db)["status"] == "insufficient_data"
    assert analyze_ueba_signals({"metadata": {"behavior": {"bytes_out": object()}}})["bytes_out"] == 0.0
    assert recall_threat_context(db_session, target=None, fingerprint=None) == []

    audit_record = AuditRecord(
        record_id="rec-invalid-json",
        sequence_number=1,
        payload="{bad",
        result=None,
        chain_hash="h",
        content_hash="c",
        signature="s",
        timestamp=datetime.now(UTC),
    )
    assert audit_router._payload(audit_record)["raw"] == "{bad"
    auth_router._FAILED_LOGINS["blocked"] = [time.time()] * auth_router.MAX_ATTEMPTS_PER_WINDOW
    with pytest.raises(HTTPException):
        auth_router.login(
            user=type("Login", (), {"username": "u", "password": "p"})(),
            request=type("Request", (), {"client": type("Client", (), {"host": "blocked"})()})(),
            db=db_session,
        )

    monkeypatch.setattr(threats_router.ThreatService, "get_threat_by_id", lambda *_args: None)
    monkeypatch.setattr(threats_router.ThreatService, "update_threat", lambda *_args: None)
    monkeypatch.setattr(threats_router.ThreatService, "delete_threat", lambda *_args: False)
    admin = User(email="admin@example.com", role="admin")
    with pytest.raises(HTTPException):
        threats_router.get_threat(uuid4(), db_session, admin)
    with pytest.raises(HTTPException):
        threats_router.update_threat(uuid4(), object(), db_session, admin)
    with pytest.raises(HTTPException):
        threats_router.delete_threat(uuid4(), db_session, admin)

    class BadValidationThreat:
        id = "bad-validation"

        def to_dict(self):
            return {"id": "not-a-uuid"}

    class ExplodingThreat:
        id = "boom"

        def to_dict(self):
            raise RuntimeError("boom")

    service = ThreatService(db_session)
    monkeypatch.setattr(
        service.repo,
        "get_all_filtered",
        lambda **_kwargs: [BadValidationThreat(), ExplodingThreat()],
    )
    assert service.get_all_threats() == []
    assert ThreatModel(
        title="t",
        source="s",
        description="d",
        level=ThreatLevel.high,
        category=ThreatCategory.network,
        score=1,
    ).to_dict()["level"] == "high"
    assert "u@example.com" in repr(User(email="u@example.com", hashed_password="h", role="viewer"))

    monkeypatch.setattr(users_router.UserService, "reset_password", lambda *_args: None)
    with pytest.raises(HTTPException):
        users_router.reset_password(
            users_router.ResetPasswordRequest(email="other@example.com", new_password="new-password"),
            db_session,
            User(email="me@example.com", role="viewer"),
        )
    monkeypatch.setattr(users_router.UserService, "update_user", lambda *_args: None)
    monkeypatch.setattr(users_router.UserService, "delete_user", lambda *_args: False)
    with pytest.raises(HTTPException):
        users_router.update_user("missing", object(), db_session, admin)
    with pytest.raises(HTTPException):
        users_router.delete_user("missing", db_session, admin)

    assert _valid_url("ftp://bad") is False
    assert _valid_url("http://example.com", require_https=True) is False
    assert _status(False) == "not_configured"
    assert build_secops_integration_readiness("unknown")["status"] == "unknown_provider"
    assert tenant_json_loads("{bad", {}) == {}
    with pytest.raises(RuntimeError):
        github_provider._repo({})
    with pytest.raises(RuntimeError):
        github_provider._repo({"target": "repo-only"})
    with pytest.raises(RuntimeError):
        github_provider.dispatch_github_command(command="devsecops.quarantine_artifact", payload={"target": "org/repo"})

    assert collect_endpoint_findings({"host": "h"}) == []
    assert collect_network_findings({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}) == []
    assert collect_k8s_findings({"namespace": "default"}) == []
    assert collect_cloud_findings({"actor": "user"}) == []

    monkeypatch.setattr("app.services.prometheus_client.requests.get", lambda *a, **k: type("R", (), {"raise_for_status": lambda self: None, "json": lambda self: {"status": "success", "data": {"alerts": {}}}})())
    assert PrometheusClient(base_url="http://prom").get_alerts() == []
    temp_logs_root = Path(".pytest-workspace-tmp") / "runtime-logs"
    if temp_logs_root.exists():
        rmtree(temp_logs_root)
    temp_logs_root.mkdir(parents=True)
    monkeypatch.chdir(temp_logs_root)
    Path("logs").mkdir()
    Path("logs/app.log").write_text("", encoding="utf-8")
    assert list_runtime_logs(limit=1)["items"] == []
    class BadHealthDb:
        def execute(self, *_args):
            raise RuntimeError("db down")

    class DownHealthClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, _url):
            raise httpx.RequestError("down")

    monkeypatch.setattr(
        "app.routers.monitoring_health.httpx.AsyncClient",
        lambda *args, **kwargs: DownHealthClient(),
    )
    assert (await monitoring_health_full(db=BadHealthDb(), _=None))["overall"] == "down"
    assert list_executions(verdict_id="v", status="success", target_entity="srv", db=fake_db)["count"] == 0
    monkeypatch.setattr(
        "app.ares.router.AutonomyService.issue_verdict_from_threat",
        lambda *_args, **_kwargs: {"status": "not_found"},
    )
    assert run_lifecycle_from_threat("missing", None, db_session)["status"] == "not_found"


def test_final_remaining_edge_contracts(monkeypatch, db_session):
    import types

    from app.ares.aggressive_containment import build_aggressive_containment
    from app.ares.enterprise_active_defense import build_enterprise_active_defense
    from app.ares.kill_switch import RedisKillSwitchStore
    from app.ares.reporter import _intelligence_trace, build_execution_result
    from app.ares.response_fabric import build_response_fabric
    from app.core import ai_provider as ai_provider_module
    from app.core import mcp_gateway, security, signing
    from app.core import secrets as secrets_module
    from app.core.mcp_context import normalize_mcp_context
    from app.db.vector import embed_text
    from app.detection.correlation import correlate_detections
    from app.identity import entra as entra_module
    from app.ingestion import kafka_consumer
    from app.ingestion.router import normalize_adapter_only
    from app.intelligence.governance import assess_llm_contract
    from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
    from app.playbooks.contracts import Playbook, PlaybookStep
    from app.playbooks.engine import build_execution_plan
    from app.redqueen.analytical_brain import build_analytical_profile
    from app.redqueen.risk_scorer import score_perception
    from app.redqueen.strategic_anticipation import build_strategic_anticipation
    from app.redqueen.trainer import build_training_report
    from app.redqueen.ueba import analyze_ueba_signals
    from app.routers import users as users_router
    from app.secops import github as github_provider
    from app.services import runtime_log_service

    assert "Threat(" in repr(
        ThreatModel(
            title="repr",
            source="manual",
            description="d",
            level=ThreatLevel.low,
            category=ThreatCategory.other,
        )
    )
    assert users_router.get_runtime_logs_for_user(limit=1, severity=None, search=None, current_user=object())["total"] >= 0
    monkeypatch.setattr(users_router.UserService, "set_user_active", lambda *_args: None)
    with pytest.raises(HTTPException):
        users_router.toggle_user_active("missing", True, db_session, object())

    class OSErrorPath:
        name = "app.log"

        def __truediv__(self, _other):
            return self

        def exists(self):
            return True

        def is_file(self):
            return True

        def open(self, *_args, **_kwargs):
            raise OSError("locked")

    monkeypatch.setattr(runtime_log_service, "Path", lambda *_args: OSErrorPath())
    assert runtime_log_service.list_runtime_logs(limit=1)["items"] == []

    class ErrorMessage:
        def value(self):
            return b"{}"

        def topic(self):
            return "raw"

        def error(self):
            return True

    class BadPayloadMessage:
        def value(self):
            return b"[]"

        def topic(self):
            return "raw"

        def error(self):
            return False

    class KafkaConsumer:
        def __init__(self, *_args, **_kwargs):
            self.messages = [ErrorMessage(), BadPayloadMessage()]

        def subscribe(self, topics):
            self.topics = topics

        def poll(self, _timeout):
            return self.messages.pop(0) if self.messages else None

        def commit(self, **_kwargs):
            self.committed = True

        def close(self):
            self.closed = True

    fake_kafka = types.SimpleNamespace(Consumer=KafkaConsumer)
    monkeypatch.setattr(kafka_consumer.settings, "KAFKA_INGESTION_ENABLED", True)
    monkeypatch.setattr(kafka_consumer, "import_module", lambda name: fake_kafka)
    result = kafka_consumer.run_kafka_consumer(on_event=lambda _event: None, max_messages=2)
    assert result["failed"] == 2

    class NoneThenBoomConsumer(KafkaConsumer):
        def poll(self, _timeout):
            if not hasattr(self, "seen_none"):
                self.seen_none = True
                return None
            raise RuntimeError("stop loop")

    monkeypatch.setattr(kafka_consumer, "import_module", lambda name: types.SimpleNamespace(Consumer=NoneThenBoomConsumer))
    with pytest.raises(RuntimeError):
        kafka_consumer.run_kafka_consumer(on_event=lambda _event: None, max_messages=None)

    with pytest.raises(HTTPException):
        normalize_adapter_only("unsupported-adapter", {})

    monkeypatch.setattr(github_provider, "get_secret", lambda name, default=None: "token")
    monkeypatch.setattr(github_provider.settings, "GITHUB_DEFAULT_OWNER", "")
    with pytest.raises(RuntimeError):
        github_provider.dispatch_github_command(
            command="devsecops.quarantine_artifact",
            payload={"target": "org/repo", "finding": {}},
        )

    class FailingResponse:
        status_code = 500
        headers = {}

        def raise_for_status(self):
            raise requests.HTTPError("provider failed")

    monkeypatch.setattr(github_provider.requests, "delete", lambda *args, **kwargs: FailingResponse())
    with pytest.raises(requests.HTTPError):
        github_provider.dispatch_github_command(
            command="devsecops.quarantine_artifact",
            payload={"target": "org/repo", "finding": {"artifact_id": "artifact-1"}},
        )
    monkeypatch.setattr(github_provider.settings, "GITHUB_TOKEN_SECRET_NAMES", "SECRET_A")
    with pytest.raises(requests.HTTPError):
        github_provider.dispatch_github_command(
            command="devsecops.revoke_pipeline_token",
            payload={"target": "org/repo"},
        )

    assert analyze_ueba_signals({"metadata": {"behavior": {"failed_logins": object(), "bytes_out": 1_000_000_000}}})[
        "signals"
    ][0] == "ueba:large_egress"
    assert score_perception(
        {
            "siem": {"active_minutes": 15},
            "metadata": {"behavior": {"bytes_out": 1_000_000_000}},
        }
    )["risk_score"] >= 0
    assert build_analytical_profile(
        target="srv",
        risk_score=90,
        action_type="observe",
        factors=["data_exfiltration"],
        controls={},
    )["contradiction_count"] == 1
    assert build_strategic_anticipation(
        target="srv",
        risk_score=10,
        factors=[],
        anticipation={"attack_stages": []},
        bridge_trace={},
    )["stage_velocity"] == "watch"
    assert build_strategic_anticipation(
        target="srv",
        risk_score=60,
        factors=[],
        anticipation={"attack_stages": []},
        bridge_trace={},
    )["intervention_window"] == "1-4h"

    assert correlate_detections(
        [{"entity_id": "srv", "severity": 8, "kill_chain_stage": "execution", "recommended_action": "endpoint_isolate"}]
    )["incidents"][0]["recommended_action"] == "endpoint_isolate"
    assert mcp_gateway.evaluate_mcp_tool_policy(
        {"tools": ["identity.lookup"], "blocked_tools": ["identity.lookup"]}
    )["code"] == "mcp_tool_blocked"
    assert normalize_mcp_context({"exposed_to_internet": "yes"})["exposed_to_internet"] is True
    assert embed_text("", dimensions=2) == [0.0, 0.0]
    assert build_aggressive_containment(verdict={}, bridge_trace=[], controls={})["bridge_trace"] == {}
    assert build_enterprise_active_defense(verdict={}, bridge_trace=[], controls={})["controls"]
    assert build_response_fabric(
        verdict={"execution_controls": {"tenant_id": "tenant-a"}},
        strategic_anticipation={"next_best_actions": [{"action": "case", "provider_family": "case"}]},
        enterprise_active_defense={},
        controls={"tenant_provider_policy": {"case": ["jira"]}, "configured_connector_secrets": {"jira": {}}},
    )["tenant_id"] == "tenant-a"
    assert _intelligence_trace({"execution_controls": []})["action_domain"] == ""
    assert build_execution_result(verdict={"execution_controls": {}}, execution={"status": "success"})["rl_reward"] == 1.0
    assert assess_llm_contract({"guardrail_decisions": "bad"})["present_guardrails"] == []
    assert ai_provider_module.SafeAIProvider.parse_json("```json\n{bad\n```") == {}
    monkeypatch.setattr(secrets_module.settings, "ENV", "development")
    assert secrets_module.validate_production_secret_backend() is None
    class SecretBox:
        def get_secret_value(self):
            return "secret"

    monkeypatch.setattr(signing.settings, "SECRET_KEY", SecretBox())
    assert len(signing.sign_payload({"a": 1})) == 64
    monkeypatch.setattr(security.pwd_context, "verify", lambda plain, hashed: True)
    assert security.verify_password("a", "b") is True
    with pytest.raises(HTTPException):
        security.require_admin_or_monitor_token(
            authorization="Bearer invalid",
            db=type("Db", (), {})(),
        )
    assert entra_module._occurred_at({"createdDateTime": "bad-date"}) is None

    class EmptyQuery:
        def order_by(self, *_args):
            return self

        def limit(self, *_args):
            return self

        def all(self):
            return []

    training_db = type("TrainingDb", (), {"query": lambda self, model: EmptyQuery()})()
    assert build_training_report(training_db)["recommendations"] == ["collect_more_execution_feedback"]
    playbook = Playbook(
        playbook_id="pb2",
        name="PB2",
        version="1",
        description="",
        steps=[
            PlaybookStep(
                step_id="s1",
                connector="c",
                action="a",
                when={"contains": {"text": "needle"}, "min": {"risk": 10}},
            )
        ],
    )
    assert build_execution_plan(playbook, context={"text": "nope", "risk": 1})["skipped"]

    class RedisClient:
        def __init__(self):
            self.data = "[]"

        def get(self, key):
            return self.data

        def set(self, key, value):
            self.data = value

        def scan_iter(self, match):
            return ["k"]

        def delete(self, key):
            self.deleted = key

    class RedisModule:
        class Redis:
            @staticmethod
            def from_url(*_args, **_kwargs):
                return RedisClient()

    monkeypatch.setattr("app.ares.kill_switch.redis", RedisModule)
    redis_store = RedisKillSwitchStore(url="redis://localhost:6379/0", key_prefix="prefix:", key=":kill")
    assert redis_store.key == "prefix:kill"
    with pytest.raises(ValueError):
        redis_store.read()
    redis_store.reset()


def test_final_last_coverage_edges(monkeypatch, db_session):
    import ast
    import importlib
    import logging
    import os

    import app.main as main_module
    from app.ares import aggressive_containment, enterprise_active_defense, internal_firewall
    from app.ares.router import _json_loads as ares_router_json_loads
    from app.code_intelligence import analyzer
    from app.core import ai_provider as ai_provider_module
    from app.core import rate_limit as rate_limit_module
    from app.core import replay_guard as replay_guard_module
    from app.core import security
    from app.core.mcp_context import normalize_mcp_context
    from app.db import session as session_module
    from app.db import vector as vector_module
    from app.identity import router as identity_router
    from app.identity.service import summarize_identity_activity
    from app.ingestion.router import normalize_adapter_only
    from app.intelligence.readiness import build_enterprise_ai_readiness
    from app.playbooks.contracts import Playbook, PlaybookStep
    from app.playbooks.engine import build_execution_plan
    from app.redqueen import router as redqueen_router
    from app.redqueen.risk_scorer import score_perception
    from app.redqueen.trainer import build_training_report
    from app.repositories.threat_repository import ThreatRepository

    assert aggressive_containment._dict([]) == {}
    assert enterprise_active_defense._dict([]) == {}
    assert internal_firewall.evaluate_internal_firewall(
        verdict={},
        plan={"action_type": "observe", "target": "srv"},
        advisor_review={"mcp_action_policy": {"allowed": False, "code": "deny"}},
    ).code == "deny"
    assert ares_router_json_loads(None, []) == []
    assert redqueen_router._json_loads(None, {}) == {}

    assert analyzer._call_name(ast.Constant(value=1)) == ""
    parsed = ast.parse("@app.on_event('startup')\ndef startup():\n    pass\n")
    function = parsed.body[0]
    assert isinstance(function, ast.FunctionDef)
    assert analyzer._decorator_name(function.decorator_list[0]) == "app.on_event"

    assert ai_provider_module.SafeAIProvider.parse_json("```json\n{\"bad\":}\n```") == {}
    assert normalize_mcp_context({"critical_dependency": 1})["critical_dependency"] is True

    monkeypatch.setattr(rate_limit_module.settings, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(rate_limit_module, "redis", None)
    with pytest.raises(RuntimeError):
        rate_limit_module._build_store()
    monkeypatch.setattr(replay_guard_module.settings, "REPLAY_GUARD_BACKEND", "redis")
    monkeypatch.setattr(replay_guard_module, "redis", None)
    with pytest.raises(RuntimeError):
        replay_guard_module._build_store()

    token_without_subject = security.create_access_token({"role": "admin"})
    with pytest.raises(HTTPException):
        security.require_admin_or_monitor_token(authorization=f"Bearer {token_without_subject}", db=db_session)

    class FakeDigest:
        calls = 0

        def __init__(self, _raw):
            pass

        def digest(self):
            FakeDigest.calls += 1
            sign_byte = 2 if FakeDigest.calls == 1 else 3
            return b"\x00\x00\x00\x00" + bytes([sign_byte]) + (b"\x00" * 27)

    monkeypatch.setattr(vector_module.hashlib, "sha256", FakeDigest)
    assert vector_module.embed_text("a b", dimensions=1) == [0.0]

    class IdentityRequest:
        headers = {"x-forwarded-for": " 10.0.0.1, 10.0.0.2"}
        client = None

    assert identity_router._client_ip(IdentityRequest()) == "10.0.0.1"
    monkeypatch.setattr(identity_router.settings, "ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED", False)
    assert identity_router._enforce_entra_replay_guard(
        db_session,
        request=IdentityRequest(),
        body=b"{}",
        payload={},
        signature=None,
        timestamp=None,
        enterprise_context={},
    ) is None
    monkeypatch.setattr(
        identity_router,
        "persist_identity_event",
        lambda db, signal: (type("Event", (), {"id": "evt-1"})(), False),
    )
    monkeypatch.setattr(
        identity_router.AutonomyService,
        "issue_verdict_from_threat_event",
        lambda *_args, **_kwargs: {"status": "not_found"},
    )
    lifecycle = identity_router.run_identity_lifecycle(
        identity_router.IdentityLifecycleRequest(
            signal=identity_router.IdentitySignal(
                provider="entra",
                event_id="identity-event-1",
                event_type="risky_login",
                identity_id="user@example.com",
            )
        ),
        db_session,
        {},
    )
    assert lifecycle["status"] == "not_found"

    event_row = type(
        "IdentityEventRow",
        (),
        {
            "event_type": "login",
            "risk_score": 60,
            "normalized_payload": json.dumps({"provider": "entra", "identity_context": {"signals": ["s"]}}),
            "normalized": "{}",
        },
    )()

    class ScalarRows:
        def all(self):
            return [event_row]

    identity_db = type("IdentityDb", (), {"scalars": lambda self, query: ScalarRows()})()
    assert summarize_identity_activity(identity_db, entity_id="user@example.com")["risk_level"] == "high"

    with pytest.raises(HTTPException):
        normalize_adapter_only("missing-adapter", {})
    assert score_perception({"metadata": {"behavior": {"bytes_out": 1_000_000_000}}})["risk_score"] >= 5

    class MostlyReadyRepo:
        provider = "persistent"

        def status(self):
            return {
                "provider": "persistent",
                "persistent": True,
                "document_count": 1,
                "versioned_documents": True,
                "latest_versions": {"security": "v1"},
                "storage_contract": "ok",
            }

        def search(self, **_kwargs):
            return []

    monkeypatch.setattr(
        "app.intelligence.readiness.build_enterprise_intelligence_status",
        lambda repository: {
            "rag": {
                "persistent": True,
                "versioned_documents": True,
                "latest_versions": {"security": "v1"},
                "provider": "persistent",
                "document_count": 1,
                "storage_contract": "ok",
            },
            "llm": {
                "decision_schema": "redqueen.llm_decision.v1",
                "governance": {
                    "schema": "vaelqorix.llm_governance.v1",
                    "ares_execution_requires_approved_contract": True,
                    "decision_trace_schema": "vaelqorix.llm_decision_trace.v1",
                },
            },
            "mcp": {"governed_execution": True},
        },
    )
    readiness = build_enterprise_ai_readiness(
        MostlyReadyRepo(),
        ai_evaluation={
            "schema": "vaelqorix.ai_evaluation.v1",
            "sample_count": 0,
            "approved_for_ares_rate": 0.0,
            "traceable_result_rate": 0.0,
        },
    )
    assert readiness["overall"] == "contract_ready_waiting_for_feedback"

    playbook = Playbook(
        playbook_id="pb3",
        name="PB3",
        version="1",
        description="",
        steps=[
            PlaybookStep(
                step_id="s1",
                connector="c",
                action="a",
                when={"contains": {"items": "missing"}, "min": {"risk": "bad"}},
            )
        ],
    )
    assert build_execution_plan(playbook, context={"items": ["ok"], "risk": "bad"})["skipped"]

    class EmptyQuery:
        def order_by(self, *_args):
            return self

        def limit(self, *_args):
            return self

        def all(self):
            return []

    training_db = type("TrainingDb", (), {"query": lambda self, model: EmptyQuery()})()
    assert build_training_report(training_db)["sample_count"] == 0
    assert ThreatRepository(db_session)._normalize_id(uuid4()) != ""

    old_handler = main_module.RotatingFileHandler
    old_handlers = list(main_module.logger.handlers)
    try:
        class DeniedHandler:
            def __init__(self, *_args, **_kwargs):
                raise PermissionError("denied")

        main_module.RotatingFileHandler = DeniedHandler
        main_module.logger.handlers.clear()
        importlib.reload(main_module)
        assert any(isinstance(handler, logging.StreamHandler) for handler in main_module.logger.handlers)
    finally:
        main_module.RotatingFileHandler = old_handler
        main_module.logger.handlers[:] = old_handlers
        importlib.reload(main_module)

    original_env = {
        key: os.environ.get(key)
        for key in [
            "PROMETHEUS_BASE_URL",
            "ALERTMANAGER_BASE_URL",
            "VAELQORIX_CORRELATION_INTERVAL_SEC",
            "VAELQORIX_CORRELATION_STARTUP_DELAY_SEC",
        ]
    }
    import app.core.settings as settings_module

    original_settings_object = settings_module.settings
    try:
        os.environ["PROMETHEUS_BASE_URL"] = "http://localhost:9090"
        os.environ["ALERTMANAGER_BASE_URL"] = "http://localhost:9093"
        os.environ["VAELQORIX_CORRELATION_INTERVAL_SEC"] = "1"
        os.environ["VAELQORIX_CORRELATION_STARTUP_DELAY_SEC"] = "-1"

        importlib.reload(settings_module)
        assert settings_module.settings.PROMETHEUS_BASE_URL.startswith("http://127.0.0.1")
        assert settings_module.settings.ALERTMANAGER_BASE_URL.startswith("http://127.0.0.1")
        assert settings_module.settings.VAELQORIX_CORRELATION_INTERVAL_SEC == 5
        assert settings_module.settings.VAELQORIX_CORRELATION_STARTUP_DELAY_SEC == 0
    finally:
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        settings_module.settings = original_settings_object

    old_db_uri = session_module.settings.SQLALCHEMY_DATABASE_URI
    try:
        session_module.settings.SQLALCHEMY_DATABASE_URI = "sqlite:///./coverage-session-reload.db"
        reloaded_session = importlib.reload(session_module)
        assert reloaded_session.engine_kwargs["connect_args"]["check_same_thread"] is False
    finally:
        session_module.settings.SQLALCHEMY_DATABASE_URI = old_db_uri
        importlib.reload(session_module)


@pytest.mark.asyncio
async def test_final_eleven_line_edges(monkeypatch, db_session):
    import importlib
    import logging.handlers

    import app.main as main_module
    from app.code_intelligence import analyzer
    from app.ingestion.router import normalize_adapter_only
    from app.playbooks.contracts import Playbook, PlaybookStep
    from app.playbooks.engine import build_execution_plan
    from app.redqueen.risk_scorer import score_perception
    from app.redqueen.trainer import _build_ai_governance_report, build_training_report

    temp_root = Path(".pytest-workspace-tmp") / "code-analyzer-on-event"
    if temp_root.exists():
        rmtree(temp_root)
    temp_root.mkdir(parents=True)
    try:
        source = temp_root / "worker.py"
        source.write_text("@app.on_event('startup')\ndef startup():\n    pass\n", encoding="utf-8")
        monkeypatch.setattr(analyzer, "BACKEND_ROOT", temp_root)
        component, _risks = analyzer._inspect_file(source, include_private=True)
        assert "event:startup" in component.execution_points
    finally:
        rmtree(temp_root)

    normalized = normalize_adapter_only(
        "wazuh",
        {"rule": {"id": "100", "level": 12, "description": "critical"}, "agent": {"name": "host-1"}},
    )
    assert normalized["level"] == "critical"

    playbook = Playbook(
        playbook_id="pb4",
        name="PB4",
        version="1",
        description="",
        steps=[
            PlaybookStep(
                step_id="s1",
                connector="c",
                action="a",
                when={"min": {"risk": 10}},
            )
        ],
    )
    assert build_execution_plan(playbook, context={"risk": "bad"})["skipped"]
    assert build_execution_plan(playbook, context={"risk": 5})["skipped"]
    assert score_perception({"ueba": {"signals": ["ueba:large_egress"]}})["risk_score"] >= 63

    verdict = type("VerdictRow", (), {"execution_controls": "{}", "action_type": "observe", "confidence": 0.9})()
    assert _build_ai_governance_report({"v1": verdict}, {})["sample_count"] == 0

    class OneVerdictQuery:
        def order_by(self, *_args):
            return self

        def limit(self, *_args):
            return self

        def all(self):
            return [type("VerdictRow", (), {"verdict_id": "v1"})()]

    class EmptyResultQuery(OneVerdictQuery):
        def filter(self, *_args):
            return self

        def all(self):
            return []

    class TrainingDb:
        calls = 0

        def query(self, _model):
            self.calls += 1
            return OneVerdictQuery() if self.calls == 1 else EmptyResultQuery()

    assert build_training_report(TrainingDb())["sample_count"] == 0

    class DeniedRotatingFileHandler:
        def __init__(self, *_args, **_kwargs):
            raise PermissionError("denied")

    old_rotating = logging.handlers.RotatingFileHandler
    old_main_handlers = list(main_module.logger.handlers)
    try:
        logging.handlers.RotatingFileHandler = DeniedRotatingFileHandler
        main_module.logger.handlers.clear()
        importlib.reload(main_module)
        assert any(isinstance(handler, logging.StreamHandler) for handler in main_module.logger.handlers)
    finally:
        logging.handlers.RotatingFileHandler = old_rotating
        main_module.logger.handlers[:] = old_main_handlers
        importlib.reload(main_module)

    class BadSession:
        def close(self):
            self.closed = True

    class BadEngine:
        def run_correlation(self, _db):
            raise RuntimeError("correlation boom")

    sleeps = {"count": 0}

    async def fake_sleep(_seconds):
        sleeps["count"] += 1
        if sleeps["count"] >= 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(main_module.settings, "VAELQORIX_CORRELATION_STARTUP_DELAY_SEC", 0)
    monkeypatch.setattr(main_module.settings, "VAELQORIX_CORRELATION_INTERVAL_SEC", 1)
    monkeypatch.setattr(main_module, "SessionLocal", lambda: BadSession())
    monkeypatch.setattr(main_module, "correlation_engine", BadEngine())
    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await main_module.correlation_worker()
