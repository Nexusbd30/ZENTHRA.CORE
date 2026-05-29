from __future__ import annotations

from dataclasses import dataclass

DEVSECOPS_COMMANDS = {
    "devsecops.resolve_pipeline",
    "devsecops.require_release_approval",
    "devsecops.revoke_pipeline_token",
    "devsecops.quarantine_artifact",
    "devsecops.block_deployment",
    "devsecops.notify_release_owner",
    "devsecops.rollback",
}

DEVSECOPS_ACTION_REQUIRED_COMMANDS: dict[str, frozenset[str]] = {
    "require_release_approval": frozenset(
        {"devsecops.resolve_pipeline", "devsecops.require_release_approval"}
    ),
    "revoke_pipeline_token": frozenset(
        {"devsecops.resolve_pipeline", "devsecops.revoke_pipeline_token"}
    ),
    "quarantine_artifact": frozenset(
        {"devsecops.resolve_pipeline", "devsecops.quarantine_artifact"}
    ),
    "block_deployment": frozenset(
        {"devsecops.resolve_pipeline", "devsecops.block_deployment"}
    ),
}


@dataclass(frozen=True)
class DevSecOpsProviderCapabilities:
    provider: str
    commands: frozenset[str]
    supports_webhook_bridge: bool = True
    notes: str = ""


PROVIDER_CAPABILITIES: dict[str, DevSecOpsProviderCapabilities] = {
    "github_actions": DevSecOpsProviderCapabilities("github_actions", frozenset(DEVSECOPS_COMMANDS)),
    "gitlab_ci": DevSecOpsProviderCapabilities("gitlab_ci", frozenset(DEVSECOPS_COMMANDS)),
    "azure_devops": DevSecOpsProviderCapabilities(
        "azure_devops",
        frozenset(
            {
                "devsecops.resolve_pipeline",
                "devsecops.require_release_approval",
                "devsecops.quarantine_artifact",
                "devsecops.block_deployment",
                "devsecops.notify_release_owner",
                "devsecops.rollback",
            }
        ),
    ),
    "jenkins": DevSecOpsProviderCapabilities(
        "jenkins",
        frozenset(
            {
                "devsecops.resolve_pipeline",
                "devsecops.require_release_approval",
                "devsecops.block_deployment",
                "devsecops.notify_release_owner",
                "devsecops.rollback",
            }
        ),
        notes="Jenkins token revocation and artifact quarantine normally require plugin-specific bridges.",
    ),
    "sonarqube": DevSecOpsProviderCapabilities(
        "sonarqube",
        frozenset(
            {
                "devsecops.resolve_pipeline",
                "devsecops.require_release_approval",
                "devsecops.notify_release_owner",
            }
        ),
        notes="Scanner-only providers can gate releases but do not directly block deployments.",
    ),
    "secops": DevSecOpsProviderCapabilities(
        "secops",
        frozenset(DEVSECOPS_COMMANDS),
        notes="Internal provider for materialized SecOps correlation events.",
    ),
    "custom": DevSecOpsProviderCapabilities(
        "custom",
        frozenset(DEVSECOPS_COMMANDS),
        notes="Custom providers must enforce provider-specific safety in the bridge.",
    ),
}


def normalize_provider(provider: str | None) -> str:
    normalized = str(provider or "custom").strip().lower().replace("-", "_")
    return normalized or "custom"


def get_provider_capabilities(provider: str | None) -> DevSecOpsProviderCapabilities:
    normalized = normalize_provider(provider)
    if normalized not in PROVIDER_CAPABILITIES:
        raise ValueError(f"Unsupported DevSecOps provider '{provider}'")
    return PROVIDER_CAPABILITIES[normalized]


def validate_devsecops_command(
    provider: str | None,
    command: str,
) -> DevSecOpsProviderCapabilities:
    capabilities = get_provider_capabilities(provider)
    if command not in capabilities.commands:
        raise ValueError(
            f"DevSecOps provider '{capabilities.provider}' does not support command '{command}'"
        )
    return capabilities


def validate_devsecops_action(
    provider: str | None,
    action_type: str,
) -> DevSecOpsProviderCapabilities:
    action = str(action_type or "").strip().lower()
    required_commands = DEVSECOPS_ACTION_REQUIRED_COMMANDS.get(action)
    capabilities = get_provider_capabilities(provider)
    if not required_commands:
        return capabilities

    missing = sorted(required_commands - capabilities.commands)
    if missing:
        raise ValueError(
            f"DevSecOps provider '{capabilities.provider}' does not support action '{action}' "
            f"(missing commands: {', '.join(missing)})"
        )
    return capabilities


def is_devsecops_action_supported(provider: str | None, action_type: str) -> bool:
    try:
        validate_devsecops_action(provider, action_type)
    except ValueError:
        return False
    return True


def strongest_supported_devsecops_action(provider: str | None, risk_score: float) -> str:
    try:
        capabilities = get_provider_capabilities(provider)
    except ValueError:
        return "soar_delegate"

    if risk_score >= 90:
        candidates = [
            "block_deployment",
            "quarantine_artifact",
            "revoke_pipeline_token",
            "require_release_approval",
        ]
    elif risk_score >= 80:
        candidates = [
            "quarantine_artifact",
            "block_deployment",
            "revoke_pipeline_token",
            "require_release_approval",
        ]
    elif risk_score >= 65:
        candidates = [
            "revoke_pipeline_token",
            "quarantine_artifact",
            "block_deployment",
            "require_release_approval",
        ]
    elif risk_score >= 45:
        candidates = ["require_release_approval", "block_deployment"]
    else:
        candidates = ["observe"]

    for candidate in candidates:
        required_commands = DEVSECOPS_ACTION_REQUIRED_COMMANDS.get(candidate, frozenset())
        if required_commands <= capabilities.commands:
            return candidate
    return "soar_delegate"


def supported_actions(provider: str | None) -> list[str]:
    capabilities = get_provider_capabilities(provider)
    actions = [
        action
        for action, required_commands in DEVSECOPS_ACTION_REQUIRED_COMMANDS.items()
        if required_commands <= capabilities.commands
    ]
    return sorted(actions)


def provider_capability_payload(provider: str | None) -> dict:
    capabilities = get_provider_capabilities(provider)
    return {
        "provider": capabilities.provider,
        "commands": sorted(capabilities.commands),
        "actions": supported_actions(capabilities.provider),
        "supports_webhook_bridge": capabilities.supports_webhook_bridge,
        "notes": capabilities.notes,
    }


def list_provider_capability_payloads() -> list[dict]:
    return [provider_capability_payload(provider) for provider in sorted(PROVIDER_CAPABILITIES)]


def action_preflight_payload(provider: str | None, action_type: str) -> dict:
    capabilities = get_provider_capabilities(provider)
    action = str(action_type or "").strip().lower()
    supported = is_devsecops_action_supported(capabilities.provider, action)
    recommended_action = (
        action if supported else strongest_supported_devsecops_action(capabilities.provider, 100.0)
    )
    return {
        "provider": capabilities.provider,
        "action_type": action,
        "supported": supported,
        "recommended_action": recommended_action,
        "adjusted": recommended_action != action,
        "supported_actions": supported_actions(capabilities.provider),
        "reason": "supported" if supported else "provider_capability_missing",
    }
