from __future__ import annotations

from typing import Any

from app.connectors.contracts import ConnectorCapability, preflight, provider_evidence, readiness

CONNECTORS: dict[str, ConnectorCapability] = {
    "paloalto": ConnectorCapability(
        provider="paloalto",
        family="firewall_waf_ndr",
        actions=["block_ip", "block_asn", "block_domain", "deploy_prevention_rule", "rollback_block"],
        reversible_actions=["block_ip", "block_asn", "block_domain", "deploy_prevention_rule"],
        required_secrets=["PALOALTO_API_KEY", "PALOALTO_BASE_URL"],
        evidence_kind="firewall_provider_action",
    ),
    "cisco": ConnectorCapability(
        provider="cisco",
        family="firewall_waf_ndr",
        actions=["block_ip", "block_domain", "deploy_prevention_rule", "query"],
        reversible_actions=["block_ip", "block_domain", "deploy_prevention_rule"],
        required_secrets=["CISCO_API_KEY", "CISCO_BASE_URL"],
        evidence_kind="network_provider_action",
    ),
    "fortinet": ConnectorCapability(
        provider="fortinet",
        family="firewall_waf_ndr",
        actions=["block_ip", "block_country", "block_domain", "rollback_block"],
        reversible_actions=["block_ip", "block_country", "block_domain"],
        required_secrets=["FORTINET_API_KEY", "FORTINET_BASE_URL"],
        evidence_kind="firewall_provider_action",
    ),
    "crowdstrike": ConnectorCapability(
        provider="crowdstrike",
        family="edr",
        actions=["isolate_endpoint", "release_endpoint", "snapshot_forensics", "deploy_detection_rule"],
        reversible_actions=["isolate_endpoint", "deploy_detection_rule"],
        required_secrets=["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"],
        evidence_kind="edr_provider_action",
    ),
    "defender": ConnectorCapability(
        provider="defender",
        family="edr",
        actions=["isolate_endpoint", "release_endpoint", "snapshot_forensics", "deploy_detection_rule"],
        reversible_actions=["isolate_endpoint", "deploy_detection_rule"],
        required_secrets=["DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"],
        evidence_kind="edr_provider_action",
    ),
    "sentinelone": ConnectorCapability(
        provider="sentinelone",
        family="edr",
        actions=["isolate_endpoint", "release_endpoint", "snapshot_forensics"],
        reversible_actions=["isolate_endpoint"],
        required_secrets=["SENTINELONE_API_TOKEN", "SENTINELONE_BASE_URL"],
        evidence_kind="edr_provider_action",
    ),
    "splunk": ConnectorCapability(
        provider="splunk",
        family="siem",
        actions=["deploy_detection_rule", "create_notable", "query"],
        reversible_actions=["deploy_detection_rule"],
        required_secrets=["SPLUNK_TOKEN", "SPLUNK_BASE_URL"],
        evidence_kind="siem_provider_action",
    ),
    "sentinel": ConnectorCapability(
        provider="sentinel",
        family="siem",
        actions=["deploy_detection_rule", "create_incident", "query"],
        reversible_actions=["deploy_detection_rule"],
        required_secrets=["SENTINEL_WORKSPACE_ID", "SENTINEL_CLIENT_SECRET"],
        evidence_kind="siem_provider_action",
    ),
    "qradar": ConnectorCapability(
        provider="qradar",
        family="siem",
        actions=["deploy_detection_rule", "create_offense_note", "query"],
        reversible_actions=["deploy_detection_rule"],
        required_secrets=["QRADAR_TOKEN", "QRADAR_BASE_URL"],
        evidence_kind="siem_provider_action",
    ),
    "servicenow": ConnectorCapability(
        provider="servicenow",
        family="soar_case",
        actions=["create_case", "update_case", "attach_evidence"],
        reversible_actions=[],
        required_secrets=["SERVICENOW_USER", "SERVICENOW_PASSWORD", "SERVICENOW_BASE_URL"],
        evidence_kind="case_provider_action",
    ),
    "jira": ConnectorCapability(
        provider="jira",
        family="case",
        actions=["create_case", "update_case", "attach_evidence"],
        reversible_actions=[],
        required_secrets=["JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_BASE_URL"],
        evidence_kind="case_provider_action",
    ),
    "openshift": ConnectorCapability(
        provider="openshift",
        family="redhat",
        actions=["cordon_workload", "apply_network_policy", "create_route", "query"],
        reversible_actions=["cordon_workload", "apply_network_policy", "create_route"],
        required_secrets=["OPENSHIFT_TOKEN", "OPENSHIFT_API_URL"],
        evidence_kind="redhat_provider_action",
    ),
    "rhacs": ConnectorCapability(
        provider="rhacs",
        family="redhat",
        actions=["deploy_policy", "quarantine_deployment", "query"],
        reversible_actions=["deploy_policy", "quarantine_deployment"],
        required_secrets=["RHACS_TOKEN", "RHACS_BASE_URL"],
        evidence_kind="redhat_provider_action",
    ),
    "quay": ConnectorCapability(
        provider="quay",
        family="redhat",
        actions=["quarantine_artifact", "block_repository", "query"],
        reversible_actions=["quarantine_artifact", "block_repository"],
        required_secrets=["QUAY_TOKEN", "QUAY_BASE_URL"],
        evidence_kind="redhat_provider_action",
    ),
    "ansible": ConnectorCapability(
        provider="ansible",
        family="redhat",
        actions=["run_job_template", "rollback_job_template", "query"],
        reversible_actions=["run_job_template"],
        required_secrets=["ANSIBLE_TOKEN", "ANSIBLE_BASE_URL"],
        evidence_kind="redhat_provider_action",
    ),
}


def list_connector_capabilities() -> list[dict[str, Any]]:
    return [
        {
            "provider": item.provider,
            "family": item.family,
            "actions": item.actions,
            "reversible_actions": item.reversible_actions,
            "required_secrets": item.required_secrets,
        }
        for item in CONNECTORS.values()
    ]


def connector_readiness(provider: str, configured_secrets: dict[str, str] | None = None) -> dict[str, Any]:
    capability = CONNECTORS.get(provider.strip().lower())
    if capability is None:
        return {"provider": provider, "ready": False, "code": "provider_unknown"}
    return readiness(capability, configured_secrets)


def connector_preflight(
    provider: str,
    *,
    action: str,
    target: str,
    change_ticket: str | None = None,
) -> dict[str, Any]:
    capability = CONNECTORS.get(provider.strip().lower())
    if capability is None:
        return {"provider": provider, "allowed": False, "code": "provider_unknown"}
    return preflight(capability, action=action, target=target, change_ticket=change_ticket)


def connector_execute_plan(
    provider: str,
    *,
    action: str,
    target: str,
    dry_run: bool = True,
    change_ticket: str | None = None,
) -> dict[str, Any]:
    capability = CONNECTORS.get(provider.strip().lower())
    if capability is None:
        return {"status": "failed", "code": "provider_unknown", "provider": provider}
    check = preflight(capability, action=action, target=target, change_ticket=change_ticket)
    if not check.get("allowed"):
        return {"status": "blocked", "preflight": check}
    status = "planned" if dry_run else "delegated"
    return {
        "status": status,
        "preflight": check,
        "evidence": provider_evidence(capability, action=action, target=target, status=status),
    }
