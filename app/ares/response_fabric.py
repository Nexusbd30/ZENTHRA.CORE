from __future__ import annotations

from typing import Any

from app.connectors.registry import CONNECTORS

FABRIC_SCHEMA = "vaelqorix.ares.response_fabric.v1"

FAMILY_PROVIDER_PRIORITY = {
    "firewall_waf_ndr": ["paloalto", "cisco", "fortinet"],
    "iam_idp": ["entra"],
    "edr_kubernetes_cloud": ["crowdstrike", "defender", "sentinelone", "openshift", "rhacs"],
    "scm_ci_artifact_registry": ["github_actions", "quay", "ansible"],
    "waf_edr_siem_soar": ["paloalto", "crowdstrike", "defender", "splunk", "sentinel", "qradar"],
    "case": ["servicenow", "jira"],
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _tenant_id(controls: dict[str, Any], verdict: dict[str, Any]) -> str:
    return str(
        controls.get("tenant_id")
        or _dict(verdict.get("execution_controls")).get("tenant_id")
        or "default"
    )


def _provider_candidates(provider_family: str, controls: dict[str, Any]) -> list[str]:
    tenant_policy = _dict(controls.get("tenant_provider_policy"))
    preferred = tenant_policy.get(provider_family)
    if isinstance(preferred, list) and preferred:
        return [str(item).strip().lower() for item in preferred if str(item).strip()]
    return FAMILY_PROVIDER_PRIORITY.get(provider_family, [])


def _readiness(provider: str, controls: dict[str, Any]) -> dict[str, Any]:
    if provider not in CONNECTORS:
        return {
            "provider": provider,
            "ready": provider in {"entra", "github_actions"},
            "source": "legacy_provider" if provider in {"entra", "github_actions"} else "unknown",
        }
    configured = _dict(controls.get("configured_connector_secrets")).get(provider)
    configured = configured if isinstance(configured, dict) else {}
    missing = [name for name in CONNECTORS[provider].required_secrets if not configured.get(name)]
    return {
        "provider": provider,
        "ready": not missing,
        "missing_secrets": missing,
        "source": "enterprise_connector_registry",
    }


def build_response_fabric(
    *,
    verdict: dict[str, Any],
    strategic_anticipation: dict[str, Any],
    enterprise_active_defense: dict[str, Any],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    target = str(verdict.get("target") or strategic_anticipation.get("target") or "")
    tenant = _tenant_id(controls, verdict)
    fabric_routes: list[dict[str, Any]] = []
    actions = [
        item
        for item in _list(strategic_anticipation.get("next_best_actions"))
        if isinstance(item, dict)
    ]
    for action in actions:
        provider_family = str(action.get("provider_family") or "")
        candidates = _provider_candidates(provider_family, controls)
        readiness = [_readiness(provider, controls) for provider in candidates]
        selected = next((item for item in readiness if item.get("ready")), readiness[0] if readiness else {})
        fabric_routes.append(
            {
                "action": str(action.get("action") or ""),
                "reason": str(action.get("reason") or ""),
                "urgency": str(action.get("urgency") or "near_term"),
                "provider_family": provider_family,
                "candidate_providers": readiness,
                "selected_provider": selected.get("provider", ""),
                "ready": bool(selected.get("ready", False)),
                "execution_mode": "live_ready" if selected.get("ready") else "contract_ready",
            }
        )
    blast_radius = "enterprise" if strategic_anticipation.get("business_priority") == "protect_crown_jewels" else "targeted"
    requires_human = any(route["urgency"] == "immediate" and not route["ready"] for route in fabric_routes)
    return {
        "schema": FABRIC_SCHEMA,
        "tenant_id": tenant,
        "target": target,
        "blast_radius": blast_radius,
        "response_posture": str(enterprise_active_defense.get("countermeasure_level") or "aggressive_defensive"),
        "routes": fabric_routes,
        "requires_human": requires_human or bool(verdict.get("requires_human")),
        "evidence_strategy": [
            "hash_every_provider_result",
            "preserve_redqueen_strategy",
            "preserve_ares_fabric_route",
            "export_case_and_legal_pack",
        ],
        "safety_boundary": [
            "no_hack_back",
            "owned_or_authorized_assets_only",
            "kill_switch_enforced",
            "advisor_and_firewall_gated",
        ],
    }
