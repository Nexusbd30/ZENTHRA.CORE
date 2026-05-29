from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

from app.core.settings import settings

ENTRA_GRAPH_COMMANDS = {
    "identity.resolve",
    "identity.disable_credentials",
    "identity.revoke_sessions",
    "identity.require_mfa",
    "identity.degrade_privileges",
}


@dataclass(frozen=True)
class EntraGraphConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    base_url: str
    token_url: str
    scope: str
    timeout_sec: float


def _compact(value: Any) -> str:
    return str(value or "").strip()


def _target_user_id(target: str) -> str:
    normalized = _compact(target)
    if normalized.startswith("user:"):
        normalized = normalized[5:]
    if not normalized:
        raise RuntimeError("Entra Graph target user is required")
    return normalized


def _graph_config() -> EntraGraphConfig:
    missing = [
        name
        for name, value in {
            "ENTRA_TENANT_ID": settings.ENTRA_TENANT_ID,
            "ENTRA_CLIENT_ID": settings.ENTRA_CLIENT_ID,
            "ENTRA_CLIENT_SECRET": settings.ENTRA_CLIENT_SECRET,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(f"Entra Graph credentials missing: {', '.join(missing)}")

    tenant_id = _compact(settings.ENTRA_TENANT_ID)
    token_url = _compact(settings.ENTRA_GRAPH_TOKEN_URL) or (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    )
    return EntraGraphConfig(
        tenant_id=tenant_id,
        client_id=_compact(settings.ENTRA_CLIENT_ID),
        client_secret=_compact(settings.ENTRA_CLIENT_SECRET),
        base_url=_compact(settings.ENTRA_GRAPH_BASE_URL).rstrip("/"),
        token_url=token_url,
        scope=_compact(settings.ENTRA_GRAPH_SCOPE) or "https://graph.microsoft.com/.default",
        timeout_sec=float(settings.ACTION_TIMEOUT_SEC),
    )


def _access_token(config: EntraGraphConfig) -> str:
    response = requests.post(
        config.token_url,
        data={
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "grant_type": "client_credentials",
            "scope": config.scope,
        },
        timeout=config.timeout_sec,
    )
    response.raise_for_status()
    token = _compact(response.json().get("access_token"))
    if not token:
        raise RuntimeError("Entra Graph token response did not include access_token")
    return token


def _headers(config: EntraGraphConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_access_token(config)}",
        "Content-Type": "application/json",
    }


def _graph_url(config: EntraGraphConfig, path: str) -> str:
    return f"{config.base_url}/{path.lstrip('/')}"


def _user_path(user_id: str) -> str:
    return f"users/{quote(user_id, safe='')}"


def _configured_group_ids() -> list[str]:
    return [
        item.strip()
        for item in str(settings.ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS or "").split(",")
        if item.strip()
    ]


def dispatch_entra_graph_command(*, command: str, payload: dict[str, Any]) -> dict[str, Any]:
    if command not in ENTRA_GRAPH_COMMANDS:
        raise RuntimeError(f"Unsupported Entra Graph command: {command}")

    config = _graph_config()
    headers = _headers(config)
    target = _target_user_id(str(payload.get("target") or ""))
    user_path = _user_path(target)

    if command == "identity.resolve":
        response = requests.get(
            _graph_url(config, f"{user_path}?$select=id,userPrincipalName,accountEnabled"),
            headers=headers,
            timeout=config.timeout_sec,
        )
        response.raise_for_status()
        body = response.json()
        return {
            "mode": "entra_graph",
            "command": command,
            "status": "ok",
            "provider": "entra",
            "target": target,
            "graph_user_id": body.get("id"),
            "user_principal_name": body.get("userPrincipalName"),
            "account_enabled": body.get("accountEnabled"),
        }

    if command == "identity.disable_credentials":
        response = requests.patch(
            _graph_url(config, user_path),
            json={"accountEnabled": False},
            headers=headers,
            timeout=config.timeout_sec,
        )
        response.raise_for_status()
        return {
            "mode": "entra_graph",
            "command": command,
            "status": "ok",
            "provider": "entra",
            "target": target,
            "operation": "accountEnabled=false",
        }

    if command == "identity.revoke_sessions":
        response = requests.post(
            _graph_url(config, f"{user_path}/revokeSignInSessions"),
            headers=headers,
            timeout=config.timeout_sec,
        )
        response.raise_for_status()
        return {
            "mode": "entra_graph",
            "command": command,
            "status": "ok",
            "provider": "entra",
            "target": target,
            "operation": "revokeSignInSessions",
        }

    if command == "identity.require_mfa":
        if not settings.ENTRA_REQUIRE_MFA_POLICY_URL:
            raise RuntimeError(
                "ENTRA_REQUIRE_MFA_POLICY_URL is required to enforce MFA through an approved "
                "Conditional Access or identity-governance bridge"
            )
        response = requests.post(
            settings.ENTRA_REQUIRE_MFA_POLICY_URL,
            json={"target": target, "provider": "entra", "source": "zenthra"},
            headers=headers,
            timeout=config.timeout_sec,
        )
        response.raise_for_status()
        return {
            "mode": "entra_graph_policy_bridge",
            "command": command,
            "status": "ok",
            "provider": "entra",
            "target": target,
            "operation": "require_mfa_policy_bridge",
        }

    group_ids = _configured_group_ids()
    if not group_ids:
        raise RuntimeError(
            "ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS is required to remove approved privileged groups"
        )
    removed: list[str] = []
    for group_id in group_ids:
        response = requests.delete(
            _graph_url(
                config,
                f"groups/{quote(group_id, safe='')}/members/{quote(target, safe='')}/$ref",
            ),
            headers=headers,
            timeout=config.timeout_sec,
        )
        if response.status_code not in {204, 404}:
            response.raise_for_status()
        removed.append(group_id)
    return {
        "mode": "entra_graph",
        "command": command,
        "status": "ok",
        "provider": "entra",
        "target": target,
        "operation": "remove_from_privileged_groups",
        "group_ids": removed,
    }
