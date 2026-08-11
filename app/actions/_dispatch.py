from __future__ import annotations

import uuid

import requests

from app.core.secrets import get_secret
from app.core.settings import settings
from app.identity.entra_graph import dispatch_entra_graph_command
from app.secops.github import dispatch_github_command


def dispatch_command(*, url: str | None, command: str, payload: dict) -> dict:
    mode = settings.ACTION_EXECUTION_MODE.strip().lower()
    if mode in {"mock", "dry_run"}:
        return {
            "mode": mode,
            "command": command,
            "payload": payload,
            "status": "ok",
        }

    if (
        mode in {"provider", "real"}
        and str(payload.get("provider") or "").strip().lower() == "entra"
        and settings.ENTRA_GRAPH_ENABLED
    ):
        return dispatch_entra_graph_command(command=command, payload=payload)

    if (
        mode in {"provider", "real"}
        and str(payload.get("provider") or "").strip().lower() == "github_actions"
    ):
        return dispatch_github_command(command=command, payload=payload)

    if mode != "webhook":
        raise RuntimeError(f"Unsupported ACTION_EXECUTION_MODE={mode}")

    if not url:
        raise RuntimeError("Webhook URL not configured for action executor")

    headers = {
        "Content-Type": "application/json",
        "X-Idempotency-Key": str(uuid.uuid4()),
    }
    shared_token = get_secret("ACTION_SHARED_TOKEN", settings.ACTION_SHARED_TOKEN)
    if shared_token:
        headers["Authorization"] = f"Bearer {shared_token}"

    body = {"command": command, "payload": payload}
    response = requests.post(url, json=body, headers=headers, timeout=float(settings.ACTION_TIMEOUT_SEC))
    response.raise_for_status()
    return response.json() if response.content else {"status": "ok", "command": command}
