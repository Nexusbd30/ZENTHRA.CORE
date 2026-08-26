from __future__ import annotations

from dataclasses import dataclass

IDENTITY_COMMANDS = {
    "identity.resolve",
    "identity.disable_credentials",
    "identity.require_mfa",
    "identity.revoke_sessions",
    "identity.degrade_privileges",
}

IDENTITY_ACTION_REQUIRED_COMMANDS: dict[str, frozenset[str]] = {
    "require_mfa": frozenset({"identity.resolve", "identity.require_mfa"}),
    "revoke_session": frozenset({"identity.resolve", "identity.revoke_sessions"}),
    "degrade_privileges": frozenset({"identity.resolve", "identity.degrade_privileges"}),
    "identity_lockdown": frozenset(
        {
            "identity.resolve",
            "identity.disable_credentials",
            "identity.require_mfa",
        }
    ),
}


@dataclass(frozen=True)
class IdentityProviderCapabilities:
    provider: str
    commands: frozenset[str]
    supports_webhook_bridge: bool = True
    notes: str = ""


PROVIDER_CAPABILITIES: dict[str, IdentityProviderCapabilities] = {
    "entra": IdentityProviderCapabilities("entra", frozenset(IDENTITY_COMMANDS)),
    "okta": IdentityProviderCapabilities("okta", frozenset(IDENTITY_COMMANDS)),
    "auth0": IdentityProviderCapabilities(
        "auth0",
        frozenset(
            {
                "identity.resolve",
                "identity.disable_credentials",
                "identity.require_mfa",
                "identity.revoke_sessions",
            }
        ),
    ),
    "keycloak": IdentityProviderCapabilities("keycloak", frozenset(IDENTITY_COMMANDS)),
    "google_workspace": IdentityProviderCapabilities(
        "google_workspace",
        frozenset(
            {
                "identity.resolve",
                "identity.disable_credentials",
                "identity.require_mfa",
                "identity.revoke_sessions",
            }
        ),
    ),
    "active_directory": IdentityProviderCapabilities(
        "active_directory",
        frozenset(
            {
                "identity.resolve",
                "identity.disable_credentials",
                "identity.degrade_privileges",
            }
        ),
    ),
    "github": IdentityProviderCapabilities(
        "github",
        frozenset(
            {
                "identity.resolve",
                "identity.require_mfa",
                "identity.revoke_sessions",
                "identity.degrade_privileges",
            }
        ),
    ),
    "aws_iam": IdentityProviderCapabilities(
        "aws_iam",
        frozenset(
            {
                "identity.resolve",
                "identity.disable_credentials",
                "identity.revoke_sessions",
                "identity.degrade_privileges",
            }
        ),
    ),
    "custom": IdentityProviderCapabilities(
        "custom",
        frozenset(IDENTITY_COMMANDS),
        notes="Custom providers must enforce provider-specific safety in the bridge.",
    ),
}


def normalize_provider(provider: str | None) -> str:
    normalized = str(provider or "custom").strip().lower().replace("-", "_")
    return normalized or "custom"


def get_provider_capabilities(provider: str | None) -> IdentityProviderCapabilities:
    normalized = normalize_provider(provider)
    if normalized not in PROVIDER_CAPABILITIES:
        raise ValueError(f"Unsupported identity provider '{provider}'")
    return PROVIDER_CAPABILITIES[normalized]


def validate_identity_command(provider: str | None, command: str) -> IdentityProviderCapabilities:
    capabilities = get_provider_capabilities(provider)
    if command not in capabilities.commands:
        raise ValueError(
            f"Identity provider '{capabilities.provider}' does not support command '{command}'"
        )
    return capabilities


def validate_identity_action(provider: str | None, action_type: str) -> IdentityProviderCapabilities:
    action = str(action_type or "").strip().lower()
    required_commands = IDENTITY_ACTION_REQUIRED_COMMANDS.get(action)
    capabilities = get_provider_capabilities(provider)
    if not required_commands:
        return capabilities

    missing = sorted(required_commands - capabilities.commands)
    if missing:
        raise ValueError(
            f"Identity provider '{capabilities.provider}' does not support action '{action}' "
            f"(missing commands: {', '.join(missing)})"
        )
    return capabilities


def is_identity_action_supported(provider: str | None, action_type: str) -> bool:
    try:
        validate_identity_action(provider, action_type)
    except ValueError:
        return False
    return True


def strongest_supported_identity_action(provider: str | None, risk_score: float) -> str:
    try:
        capabilities = get_provider_capabilities(provider)
    except ValueError:
        return "soar_delegate"

    if risk_score >= 90:
        candidates = ["identity_lockdown", "revoke_session", "degrade_privileges", "require_mfa"]
    elif risk_score >= 75:
        candidates = ["revoke_session", "degrade_privileges", "identity_lockdown", "require_mfa"]
    elif risk_score >= 60:
        candidates = ["degrade_privileges", "revoke_session", "require_mfa"]
    elif risk_score >= 40:
        candidates = ["require_mfa", "revoke_session"]
    else:
        candidates = ["observe"]

    for candidate in candidates:
        required_commands = IDENTITY_ACTION_REQUIRED_COMMANDS.get(candidate, frozenset())
        if required_commands <= capabilities.commands:
            return candidate
    return "soar_delegate"


def supported_actions(provider: str | None) -> list[str]:
    capabilities = get_provider_capabilities(provider)
    actions = [
        action
        for action, required_commands in IDENTITY_ACTION_REQUIRED_COMMANDS.items()
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
    return [
        provider_capability_payload(provider)
        for provider in sorted(PROVIDER_CAPABILITIES)
    ]


def action_preflight_payload(provider: str | None, action_type: str, risk_score: float) -> dict:
    capabilities = get_provider_capabilities(provider)
    action = str(action_type or "").strip().lower()
    supported = is_identity_action_supported(capabilities.provider, action)
    if supported:
        recommended_action = action
        reason = "supported"
    else:
        recommended_action = strongest_supported_identity_action(capabilities.provider, risk_score)
        reason = "provider_capability_adjustment"
    return {
        "provider": capabilities.provider,
        "action_type": action,
        "supported": supported,
        "recommended_action": recommended_action,
        "adjusted": recommended_action != action,
        "reason": reason,
    }
