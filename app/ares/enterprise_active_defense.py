from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

ENTERPRISE_ACTIVE_DEFENSE_SCHEMA = "vaelqorix.ares.enterprise_active_defense.v1"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _values(block_targets: list[dict[str, Any]], *types: str) -> list[str]:
    wanted = {item.lower() for item in types}
    return list(
        dict.fromkeys(
            str(item.get("value"))
            for item in block_targets
            if str(item.get("type") or "").lower() in wanted and item.get("value")
        )
    )


def _control(
    name: str,
    *,
    provider_family: str,
    actions: list[str],
    indicators: list[str],
    requires_confirmation: bool,
    reversible: bool,
    notes: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "provider_family": provider_family,
        "actions": actions,
        "indicators": indicators,
        "requires_confirmation": requires_confirmation,
        "reversible": reversible,
        "notes": notes,
    }


def build_legal_escalation_pack(
    *,
    verdict: dict[str, Any],
    bridge_trace: dict[str, Any],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    return {
        "schema": "vaelqorix.ares.legal_escalation_pack.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "case_id": str(controls.get("case_id") or verdict.get("verdict_id") or ""),
        "target": str(verdict.get("target") or bridge_trace.get("target") or ""),
        "risk_score": float(verdict.get("risk_score") or 0.0),
        "action_type": str(verdict.get("action_type") or ""),
        "evidence_sources": bridge_trace.get("evidence_sources", []),
        "origin_candidates": bridge_trace.get("origin_candidates", []),
        "pivot_chain": bridge_trace.get("pivot_chain", []),
        "recommended_recipients": [
            "internal_soc",
            "cloud_provider_abuse_desk",
            "domain_registrar_abuse_desk",
            "national_cert_or_csirt",
            "legal_counsel",
        ],
        "chain_of_custody": [
            "capture_verdict_signature",
            "capture_bridge_trace",
            "capture_action_evidence",
            "hash_evidence_bundle",
            "store_in_immutable_audit_log",
        ],
        "legal_boundaries": [
            "owned_assets_only",
            "no_unauthorized_external_access",
            "block_report_and_preserve",
        ],
    }


def build_enterprise_active_defense(
    *,
    verdict: dict[str, Any],
    bridge_trace: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    bridge_trace = bridge_trace if isinstance(bridge_trace, dict) else {}
    block_targets = _items(bridge_trace.get("block_targets"))
    ips = _values(block_targets, "network_indicator")
    asns = _values(block_targets, "asn")
    countries = _values(block_targets, "geo_country")
    domains = _values(block_targets, "domain")
    identities = _values(block_targets, "identity", "session")
    endpoints = _values(block_targets, "device", "runner", "workload")
    release_paths = _values(block_targets, "repository", "pipeline", "artifact")

    controls_plan = [
        _control(
            "perimeter_auto_block",
            provider_family="firewall_waf_ndr",
            actions=["block_ip", "block_asn", "block_country", "block_domain", "watch_egress"],
            indicators=[*ips, *asns, *countries, *domains],
            requires_confirmation=True,
            reversible=True,
            notes="Apply blocks only in owned perimeter, WAF, DNS and network controls.",
        ),
        _control(
            "identity_burn_protocol",
            provider_family="iam_idp",
            actions=["revoke_sessions", "revoke_tokens", "rotate_api_keys", "force_mfa"],
            indicators=identities,
            requires_confirmation=False,
            reversible=False,
            notes="Invalidate suspected access paths and force clean re-authentication.",
        ),
        _control(
            "endpoint_workload_isolation",
            provider_family="edr_kubernetes_cloud",
            actions=["isolate_endpoint", "quarantine_runner", "cordon_workload", "snapshot_forensics"],
            indicators=endpoints,
            requires_confirmation=True,
            reversible=True,
            notes="Contain confirmed pivots while preserving volatile evidence.",
        ),
        _control(
            "devsecops_release_freeze",
            provider_family="scm_ci_artifact_registry",
            actions=["block_deployment", "quarantine_artifact", "require_release_approval"],
            indicators=release_paths,
            requires_confirmation=True,
            reversible=True,
            notes="Freeze delivery path when bridge touches repository, pipeline or artifact.",
        ),
        _control(
            "waf_edr_siem_rule_deployment",
            provider_family="waf_edr_siem_soar",
            actions=["deploy_detection_rule", "deploy_prevention_rule", "notify_soc"],
            indicators=[*ips, *domains, *identities, *endpoints],
            requires_confirmation=False,
            reversible=True,
            notes="Push internal detection and prevention rules with idempotent provider/webhook dispatch.",
        ),
        _control(
            "deception_grid",
            provider_family="honeypot_honeytoken_canary",
            actions=["issue_honeytoken", "publish_canary_file", "route_to_internal_honeypot"],
            indicators=[*identities, *endpoints, *release_paths],
            requires_confirmation=False,
            reversible=True,
            notes="Authorized deception inside owned tenants, networks and repositories.",
        ),
        _control(
            "authorized_sinkhole",
            provider_family="owned_dns_proxy",
            actions=["sinkhole_owned_domain", "dns_rpz_block", "collect_query_telemetry"],
            indicators=domains,
            requires_confirmation=True,
            reversible=True,
            notes="Sinkhole only owned or explicitly authorized domains; otherwise block and report.",
        ),
    ]
    legal_pack = build_legal_escalation_pack(
        verdict=verdict,
        bridge_trace=bridge_trace,
        controls=controls,
    )
    return {
        "schema": ENTERPRISE_ACTIVE_DEFENSE_SCHEMA,
        "mode": "enterprise_authorized_active_defense",
        "target": str(verdict.get("target") or bridge_trace.get("target") or ""),
        "countermeasure_level": str(controls.get("countermeasure_level") or "aggressive_defensive"),
        "external_action_policy": "block_report_preserve_only",
        "controls": controls_plan,
        "execution_order": [
            "preserve_evidence",
            "identity_burn_protocol",
            "perimeter_auto_block",
            "endpoint_workload_isolation",
            "devsecops_release_freeze",
            "waf_edr_siem_rule_deployment",
            "deception_grid",
            "authorized_sinkhole",
            "legal_escalation_pack",
        ],
        "legal_escalation_pack": legal_pack,
        "guardrails": [
            "no_hack_back",
            "owned_or_authorized_assets_only",
            "human_approval_for_disruptive_controls",
            "kill_switch_enforced",
            "immutable_audit_required",
            "provider_idempotency_required",
        ],
    }
