from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import requests

from app.core.secrets import get_secret
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
    client_secret = get_secret("ENTRA_CLIENT_SECRET", settings.ENTRA_CLIENT_SECRET)
    missing = [
        name
        for name, value in {
            "ENTRA_TENANT_ID": settings.ENTRA_TENANT_ID,
            "ENTRA_CLIENT_ID": settings.ENTRA_CLIENT_ID,
            "ENTRA_CLIENT_SECRET": client_secret,
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
        client_secret=_compact(client_secret),
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


def _evidence(
    *,
    command: str,
    target: str,
    operation: str,
    graph_path: str,
    status_code: int,
    provider_request_id: str,
) -> dict[str, Any]:
    target_hash = hashlib.sha256(target.lower().encode("utf-8")).hexdigest()
    return {
        "kind": "identity_provider_graph_action",
        "provider": "entra",
        "command": command,
        "operation": operation,
        "graph_path": graph_path,
        "http_status": status_code,
        "provider_request_id": provider_request_id,
        "target_sha256": target_hash,
        "recorded_at": datetime.now(UTC).isoformat(),
        "secrets_exposed": False,
    }


def _provider_request_id(response: requests.Response) -> str:
    return (
        response.headers.get("request-id")
        or response.headers.get("client-request-id")
        or response.headers.get("x-ms-request-id")
        or str(uuid4())
    )


def _resolve_user(config: EntraGraphConfig, headers: dict[str, str], target: str) -> dict[str, Any]:
    path = f"{_user_path(target)}?$select=id,userPrincipalName,accountEnabled"
    response = requests.get(
        _graph_url(config, path),
        headers=headers,
        timeout=config.timeout_sec,
    )
    response.raise_for_status()
    body = response.json()
    return {
        "body": body,
        "path": path,
        "status_code": response.status_code,
        "provider_request_id": _provider_request_id(response),
    }


def dispatch_entra_graph_command(*, command: str, payload: dict[str, Any]) -> dict[str, Any]:
    if command not in ENTRA_GRAPH_COMMANDS:
        raise RuntimeError(f"Unsupported Entra Graph command: {command}")

    config = _graph_config()
    headers = _headers(config)
    target = _target_user_id(str(payload.get("target") or ""))
    user_path = _user_path(target)

    if command == "identity.resolve":
        resolved = _resolve_user(config, headers, target)
        body = resolved["body"]
        return {
            "mode": "entra_graph",
            "command": command,
            "status": "ok",
            "provider": "entra",
            "target": target,
            "graph_user_id": body.get("id"),
            "user_principal_name": body.get("userPrincipalName"),
            "account_enabled": body.get("accountEnabled"),
            "provider_evidence": _evidence(
                command=command,
                target=target,
                operation="resolve_user",
                graph_path=resolved["path"],
                status_code=resolved["status_code"],
                provider_request_id=resolved["provider_request_id"],
            ),
        }

    if command == "identity.disable_credentials":
        path = user_path
        response = requests.patch(
            _graph_url(config, path),
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
            "provider_evidence": _evidence(
                command=command,
                target=target,
                operation="accountEnabled=false",
                graph_path=path,
                status_code=response.status_code,
                provider_request_id=_provider_request_id(response),
            ),
        }

    if command == "identity.revoke_sessions":
        path = f"{user_path}/revokeSignInSessions"
        response = requests.post(
            _graph_url(config, path),
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
            "provider_evidence": _evidence(
                command=command,
                target=target,
                operation="revokeSignInSessions",
                graph_path=path,
                status_code=response.status_code,
                provider_request_id=_provider_request_id(response),
            ),
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
            "provider_evidence": _evidence(
                command=command,
                target=target,
                operation="require_mfa_policy_bridge",
                graph_path="external_policy_bridge",
                status_code=response.status_code,
                provider_request_id=_provider_request_id(response),
            ),
        }

    group_ids = _configured_group_ids()
    if not group_ids:
        raise RuntimeError(
            "ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS is required to remove approved privileged groups"
        )
    resolved = _resolve_user(config, headers, target)
    graph_user_id = str(resolved["body"].get("id") or "").strip()
    if not graph_user_id:
        raise RuntimeError("Entra Graph resolve did not return user id for privilege degradation")
    removed: list[str] = []
    evidence_items = [
        _evidence(
            command="identity.resolve",
            target=target,
            operation="resolve_before_degrade_privileges",
            graph_path=resolved["path"],
            status_code=resolved["status_code"],
            provider_request_id=resolved["provider_request_id"],
        )
    ]
    for group_id in group_ids:
        path = f"groups/{quote(group_id, safe='')}/members/{quote(graph_user_id, safe='')}/$ref"
        response = requests.delete(
            _graph_url(config, path),
            headers=headers,
            timeout=config.timeout_sec,
        )
        if response.status_code not in {204, 404}:
            response.raise_for_status()
        removed.append(group_id)
        evidence_items.append(
            _evidence(
                command=command,
                target=target,
                operation="remove_from_privileged_group",
                graph_path=path,
                status_code=response.status_code,
                provider_request_id=_provider_request_id(response),
            )
        )
    return {
        "mode": "entra_graph",
        "command": command,
        "status": "ok",
        "provider": "entra",
        "target": target,
        "graph_user_id": graph_user_id,
        "operation": "remove_from_privileged_groups",
        "group_ids": removed,
        "provider_evidence": {
            "kind": "identity_provider_graph_action_batch",
            "provider": "entra",
            "command": command,
            "items": evidence_items,
            "secrets_exposed": False,
        },
    }
