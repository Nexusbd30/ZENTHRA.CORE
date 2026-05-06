from __future__ import annotations

import uuid

import requests

from app.core.settings import settings


def dispatch_command(*, url: str | None, command: str, payload: dict) -> dict:
    mode = settings.ACTION_EXECUTION_MODE.strip().lower()
    if mode in {"mock", "dry_run"}:
        return {
            "mode": mode,
            "command": command,
            "payload": payload,
            "status": "ok",
        }

    if mode != "webhook":
        raise RuntimeError(f"Unsupported ACTION_EXECUTION_MODE={mode}")

    if not url:
        raise RuntimeError("Webhook URL not configured for action executor")

    headers = {
        "Content-Type": "application/json",
        "X-Idempotency-Key": str(uuid.uuid4()),
    }
    if settings.ACTION_SHARED_TOKEN:
        headers["Authorization"] = f"Bearer {settings.ACTION_SHARED_TOKEN}"

    body = {"command": command, "payload": payload}
    response = requests.post(url, json=body, headers=headers, timeout=float(settings.ACTION_TIMEOUT_SEC))
    response.raise_for_status()
    return response.json() if response.content else {"status": "ok", "command": command}
