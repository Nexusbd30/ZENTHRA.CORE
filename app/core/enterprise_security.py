from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.rate_limit import rate_limit_backend_status
from app.core.replay_guard import replay_guard_backend_status
from app.core.settings import settings
from app.identity.providers import list_provider_capability_payloads as list_identity_providers
from app.secops.providers import list_provider_capability_payloads as list_devsecops_providers

ENTERPRISE_CAPABILITIES = {
    "identity:read",
    "identity:triage",
    "identity:execute",
    "devsecops:read",
    "devsecops:triage",
    "devsecops:execute",
    "redqueen:read",
    "redqueen:train",
    "ares:read",
    "ares:execute",
    "audit:read",
    "soc:read",
    "soc:materialize",
    "soc:execute",
    "security:admin",
}

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "superadmin": frozenset(ENTERPRISE_CAPABILITIES),
    "administrator": frozenset(ENTERPRISE_CAPABILITIES),
    "admin": frozenset(ENTERPRISE_CAPABILITIES),
    "security_admin": frozenset(ENTERPRISE_CAPABILITIES),
    "secops_lead": frozenset(
        {
            "identity:read",
            "identity:triage",
            "identity:execute",
            "devsecops:read",
            "devsecops:triage",
            "devsecops:execute",
            "redqueen:read",
            "ares:read",
            "ares:execute",
            "audit:read",
            "soc:read",
            "soc:materialize",
            "soc:execute",
        }
    ),
    "analyst": frozenset(
        {
            "identity:read",
            "identity:triage",
            "devsecops:read",
            "devsecops:triage",
            "redqueen:read",
            "ares:read",
            "audit:read",
            "soc:read",
            "soc:materialize",
        }
    ),
    "viewer": frozenset(
        {
            "identity:read",
            "devsecops:read",
            "redqueen:read",
            "ares:read",
            "audit:read",
            "soc:read",
        }
    ),
    "user": frozenset({"redqueen:read"}),
}


@dataclass(frozen=True)
class EnterpriseSecurityContext:
    actor: str
    role: str
    tenant_id: str
    capabilities: frozenset[str]


def normalize_role(role: str | None) -> str:
    normalized = str(role or "user").strip().lower().replace("-", "_")
    return normalized or "user"


def normalize_tenant_id(tenant_id: str | None) -> str:
    normalized = str(tenant_id or settings.DEFAULT_TENANT_ID).strip()
    return normalized or settings.DEFAULT_TENANT_ID


def capabilities_for_role(role: str | None) -> frozenset[str]:
    return ROLE_CAPABILITIES.get(normalize_role(role), frozenset())


def has_capability(role: str | None, capability: str) -> bool:
    return capability in capabilities_for_role(role)


def build_security_context(
    *,
    actor: str,
    role: str | None,
    tenant_id: str | None = None,
) -> EnterpriseSecurityContext:
    normalized_role = normalize_role(role)
    return EnterpriseSecurityContext(
        actor=actor,
        role=normalized_role,
        tenant_id=normalize_tenant_id(tenant_id),
        capabilities=capabilities_for_role(normalized_role),
    )


def _provider_summary(providers: list[dict[str, Any]], preferred: set[str]) -> dict[str, Any]:
    names = {str(item.get("provider")) for item in providers}
    configured = sorted(names & preferred)
    return {
        "provider_count": len(providers),
        "preferred_providers": sorted(preferred),
        "preferred_available": configured,
        "coverage": "ok" if configured else "attention",
    }


def build_enterprise_readiness(*, tenant_id: str | None = None) -> dict[str, Any]:
    identity_providers = list_identity_providers()
    devsecops_providers = list_devsecops_providers()
    tenant_mode = str(settings.ENTERPRISE_TENANT_MODE or "single_tenant")
    tenant = normalize_tenant_id(tenant_id)

    return {
        "module": "enterprise_security",
        "phase": "phase_1_points_1_2",
        "overall": "ready_for_controlled_pilot",
        "tenant": {
            "tenant_id": tenant,
            "mode": tenant_mode,
            "isolation_level": "request_scoped" if tenant_mode != "single_tenant" else "logical",
            "persistent_tenant_model_required": tenant_mode != "strict",
        },
        "rbac": {
            "enabled": bool(settings.ENTERPRISE_RBAC_ENABLED),
            "roles": {
                role: sorted(capabilities)
                for role, capabilities in sorted(ROLE_CAPABILITIES.items())
            },
            "capability_count": len(ENTERPRISE_CAPABILITIES),
        },
        "audit": {
            "decision_chain": "enabled",
            "execution_chain": "enabled",
            "hash_chain": "enabled",
            "tenant_context": "persisted",
            "capability_context": "persisted",
            "capability_gate": "bound_to_identity_and_devsecops_mutations",
            "external_provider_evidence": "persisted_for_identity_webhook_events",
        },
        "integrations": {
            "identity": _provider_summary(identity_providers, {"entra", "okta"}),
            "devsecops": _provider_summary(
                devsecops_providers,
                {"github_actions", "azure_devops", "gitlab_ci"},
            ),
            "siem_soc": {
                "preferred_providers": ["microsoft_sentinel", "generic_webhook"],
                "coverage": "contract_ready",
                "enterprise_gap": "external_siem_connector_not_configured",
                "capabilities": ["soc:read", "soc:materialize", "soc:execute"],
            },
        },
        "control_urls": {
            "identity": bool(settings.IDENTITY_CONTROL_URL),
            "devsecops": bool(settings.DEVSECOPS_CONTROL_URL),
            "soar": bool(settings.SOAR_CONTROL_URL),
        },
        "security_runtime": {
            "rate_limit_store": rate_limit_backend_status(),
            "replay_guard_store": replay_guard_backend_status(),
        },
        "next_gate": "connect_first_live_identity_or_devsecops_provider",
    }
