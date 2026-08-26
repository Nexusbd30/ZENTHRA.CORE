from app.cases.service import create_case
from app.compliance.controls import compliance_evidence_snapshot
from app.connectors.registry import (
    connector_execute_plan,
    connector_preflight,
    connector_readiness,
    list_connector_capabilities,
)
from app.detection.correlation import correlate_detections
from app.detection.rules import evaluate_rules
from app.playbooks.runtime import preview_playbook
from app.runtime.orchestrator import RuntimeQueue
from app.sensors.cloud_sensor import collect_cloud_findings
from app.sensors.endpoint_agent import collect_endpoint_findings
from app.sensors.k8s_sensor import collect_k8s_findings
from app.sensors.network_sensor import collect_network_findings


def test_native_sensors_emit_aresx_compatible_events():
    endpoint = collect_endpoint_findings(
        {
            "host": "workstation-7",
            "process": "powershell",
            "command_line": "powershell -enc bad",
            "outbound_ip": "198.51.100.9",
        }
    )
    network = collect_network_findings(
        {
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.9",
            "dst_port": 4444,
            "connection_count": 4,
            "dns_query": "callback.example.test",
            "asn": "AS64500",
            "geo_country": "RU",
        }
    )
    cloud = collect_cloud_findings(
        {
            "event_name": "IAM.CreateAccessKey",
            "actor": "admin@example.com",
            "resource": "prod-tenant",
            "mfa_present": False,
        }
    )
    k8s = collect_k8s_findings(
        {
            "verb": "create",
            "resource": "pods",
            "namespace": "prod",
            "name": "prod/shell",
            "privileged": True,
        }
    )

    findings = [*endpoint, *network, *cloud, *k8s]
    events = [finding.to_aresx_event() for finding in findings]

    assert len(events) == 4
    assert {event["source"] for event in events} == {
        "native_endpoint_agent",
        "native_network_sensor",
        "native_cloud_sensor",
        "native_k8s_sensor",
    }
    assert all(event["normalized_payload"]["provider_evidence"]["kind"] == "native_sensor_finding" for event in events)


def test_detection_engine_correlates_native_sensor_events():
    finding = collect_network_findings(
        {
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.9",
            "dst_port": 4444,
            "connection_count": 4,
            "unique_hosts": 12,
            "east_west": True,
        }
    )[0]
    event = finding.to_aresx_event()
    event["signals"] = finding.signals

    matches = evaluate_rules([event])
    correlation = correlate_detections(matches)

    assert {match["rule_id"] for match in matches} >= {"VXDR-NETWORK-001", "VXDR-LATERAL-001"}
    assert correlation["incident_count"] == 1
    assert correlation["incidents"][0]["recommended_action"] == "aggressive_containment"


def test_connectors_expose_vendor_grade_contracts():
    providers = {item["provider"] for item in list_connector_capabilities()}
    assert {"paloalto", "cisco", "crowdstrike", "defender", "splunk", "openshift", "ansible"} <= providers

    readiness = connector_readiness("paloalto")
    preflight_blocked = connector_preflight("paloalto", action="block_ip", target="198.51.100.9")
    preflight_allowed = connector_preflight(
        "paloalto",
        action="block_ip",
        target="198.51.100.9",
        change_ticket="CHG-1",
    )
    execution = connector_execute_plan(
        "crowdstrike",
        action="isolate_endpoint",
        target="workstation-7",
        dry_run=True,
        change_ticket="CHG-2",
    )

    assert readiness["ready"] is False
    assert "PALOALTO_API_KEY" in readiness["missing_secrets"]
    assert preflight_blocked["allowed"] is False
    assert preflight_allowed["allowed"] is True
    assert execution["status"] == "planned"
    assert execution["evidence"]["secrets_exposed"] is False


def test_playbook_engine_supports_approval_gates_and_conditions():
    response = preview_playbook(
        playbook_id="active_defense.aggressive_containment",
        context={"risk_score": 91, "signals": ["endpoint_compromise"]},
        dry_run=True,
        approved=False,
    )

    plan = response["plan"]
    statuses = {step["step_id"]: step["status"] for step in plan["steps"]}

    assert response["status"] == "ok"
    assert plan["approval_required"] is True
    assert statuses["perimeter-block"] == "approval_required"
    assert statuses["endpoint-isolate"] == "approval_required"
    assert plan["rollback_strategy"] == "reverse_order_for_reversible_steps"


def test_case_evidence_runtime_and_compliance_foundations():
    case = create_case(
        title="Active defense incident",
        severity="critical",
        tenant_id="tenant-a",
        verdict={"verdict_id": "v-1", "target": "prod-api"},
        legal_pack={"case_id": "CASE-1"},
    )
    queue = RuntimeQueue("test", max_size=1)
    queued = queue.enqueue({"playbook_id": "active_defense.aggressive_containment"}, idempotency_key="idem-1")
    blocked = queue.enqueue({"playbook_id": "overflow"})
    compliance = compliance_evidence_snapshot({"audit_chain": "enabled"})

    assert case["case"]["tenant_id"] == "tenant-a"
    assert case["evidence_export"]["artifact_count"] == 2
    assert queued["status"] == "queued"
    assert blocked["status"] == "backpressure"
    assert compliance["frameworks"] == ["SOC2", "ISO27001"]
