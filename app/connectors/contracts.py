from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ConnectorCapability:
    provider: str
    family: str
    actions: list[str]
    reversible_actions: list[str] = field(default_factory=list)
    required_secrets: list[str] = field(default_factory=list)
    evidence_kind: str = "provider_action"


def readiness(capability: ConnectorCapability, configured_secrets: dict[str, str] | None = None) -> dict[str, Any]:
    configured_secrets = configured_secrets if isinstance(configured_secrets, dict) else {}
    missing = [name for name in capability.required_secrets if not configured_secrets.get(name)]
    return {
        "provider": capability.provider,
        "family": capability.family,
        "ready": not missing,
        "missing_secrets": missing,
        "actions": capability.actions,
        "reversible_actions": capability.reversible_actions,
    }


def preflight(
    capability: ConnectorCapability,
    *,
    action: str,
    target: str,
    change_ticket: str | None = None,
) -> dict[str, Any]:
    supported = action in capability.actions
    disruptive = action not in {"query", "notify", "create_case", "deploy_detection_rule"}
    return {
        "provider": capability.provider,
        "family": capability.family,
        "action": action,
        "target": target,
        "supported": supported,
        "allowed": supported and (not disruptive or bool(change_ticket)),
        "requires_change_ticket": disruptive,
        "reversible": action in capability.reversible_actions,
    }


def provider_evidence(
    capability: ConnectorCapability,
    *,
    action: str,
    target: str,
    status: str = "planned",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": capability.evidence_kind,
        "provider": capability.provider,
        "family": capability.family,
        "action": action,
        "target": target,
        "status": status,
        "idempotency_key": uuid4().hex,
        "recorded_at": datetime.now(UTC).isoformat(),
        "secrets_exposed": False,
        "extra": extra or {},
    }
