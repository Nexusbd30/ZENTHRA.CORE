from typing import Any

CRITICAL_BUSINESS_VALUES = {"critical", "mission_critical", "tier0", "tier_0"}
CRITICAL_ASSET_VALUES = {"crown_jewel", "tier0", "tier_0", "prod", "production"}


def _list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None][:20]


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def normalize_mcp_context(
    raw_context: dict[str, Any] | None,
    *,
    target: str | None = None,
) -> dict[str, Any]:
    raw = raw_context if isinstance(raw_context, dict) else {}
    context = {
        "source": str(raw.get("source") or "manual_context"),
        "target": str(raw.get("target") or target or "unknown"),
        "service_owner": str(raw.get("service_owner") or ""),
        "asset_tier": str(raw.get("asset_tier") or "").lower(),
        "business_criticality": str(raw.get("business_criticality") or "").lower(),
        "critical_dependency": _bool(raw.get("critical_dependency", False)),
        "exposed_to_internet": _bool(raw.get("exposed_to_internet", False)),
        "active_incident_count": _int(raw.get("active_incident_count", 0)),
        "blast_radius": str(raw.get("blast_radius") or "").lower(),
        "maintenance_window": str(raw.get("maintenance_window") or ""),
        "allowed_actions": _list(raw.get("allowed_actions")),
        "blocked_actions": _list(raw.get("blocked_actions")),
        "related_assets": _list(raw.get("related_assets")),
        "evidence_refs": _list(raw.get("evidence_refs")),
    }
    return {
        key: value
        for key, value in context.items()
        if value is not None and value != "" and value != []
    }


def mcp_risk_factors(context: dict[str, Any] | None) -> list[str]:
    context = context if isinstance(context, dict) else {}
    factors: list[str] = []
    if context.get("critical_dependency"):
        factors.append("mcp:critical_dependency")
    if str(context.get("business_criticality", "")).lower() in CRITICAL_BUSINESS_VALUES:
        factors.append(f"mcp:business_criticality:{context['business_criticality']}")
    if str(context.get("asset_tier", "")).lower() in CRITICAL_ASSET_VALUES:
        factors.append(f"mcp:asset_tier:{context['asset_tier']}")
    if str(context.get("blast_radius", "")).lower() in {"large", "high", "enterprise"}:
        factors.append(f"mcp:blast_radius:{context['blast_radius']}")
    if context.get("exposed_to_internet"):
        factors.append("mcp:internet_exposed")
    active_incidents = _int(context.get("active_incident_count", 0))
    if active_incidents:
        factors.append(f"mcp:active_incidents:{active_incidents}")
    if context.get("blocked_actions"):
        factors.append("mcp:blocked_actions_present")
    return factors
