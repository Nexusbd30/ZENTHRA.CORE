from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.core import secrets
from app.core.rate_limit import rate_limit_backend_status
from app.core.replay_guard import replay_guard_backend_status
from app.core.settings import settings
from app.ingestion.adapters import ADAPTERS
from app.secops.providers import action_preflight_payload, provider_capability_payload


def _setting_or_secret(name: str, value: str | None = None) -> bool:
    return bool((value or "").strip() or secrets.get_secret(name))


def _valid_url(value: str | None, *, require_https: bool = False) -> bool:
    parsed = urlparse(str(value or ""))
    if parsed.scheme not in {"http", "https", "redis", "rediss"}:
        return False
    if require_https and parsed.scheme != "https":
        return False
    return bool(parsed.netloc)


def _status(ok: bool, *, degraded: bool = False) -> str:
    if ok:
        return "ready"
    if degraded:
        return "degraded"
    return "not_configured"


def build_redis_readiness() -> dict[str, Any]:
    rate_limit = rate_limit_backend_status()
    replay_guard = replay_guard_backend_status()
    redis_selected = {
        rate_limit.get("backend"),
        replay_guard.get("backend"),
    } == {"redis"}
    url_valid = _valid_url(settings.REDIS_URL)
    ping: dict[str, Any] = {"attempted": False, "ok": False}
    if redis_selected and url_valid:
        ping["attempted"] = True
        try:
            import redis

            client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            ping["ok"] = bool(client.ping())
        except Exception as exc:  # pragma: no cover - exact Redis client errors vary by runtime
            ping["error"] = exc.__class__.__name__

    ready = redis_selected and url_valid and (not ping["attempted"] or ping["ok"])
    return {
        "integration": "redis",
        "status": _status(ready, degraded=bool(settings.REDIS_URL)),
        "configured": redis_selected,
        "url_configured": bool(settings.REDIS_URL),
        "url_valid": url_valid,
        "rate_limit_store": rate_limit,
        "replay_guard_store": replay_guard,
        "ping": ping,
        "production_required": True,
        "secrets_exposed": False,
    }


def build_secret_backend_readiness() -> dict[str, Any]:
    status = secrets.secret_backend_status()
    backend = str(status.get("backend") or "")
    return {
        "integration": "secret_backend",
        "status": _status(bool(status.get("production_ready")), degraded=backend == "env"),
        "configured": bool(status.get("production_ready")),
        "backend": backend,
        "file_dir": status.get("file_dir", ""),
        "configured_secrets": status.get("configured", {}),
        "missing": status.get("missing", []),
        "production_required": True,
        "secrets_exposed": False,
    }


def build_soc_webhook_readiness() -> dict[str, Any]:
    url_valid = _valid_url(settings.SOC_WEBHOOK_URL, require_https=True)
    token = _setting_or_secret("SOC_WEBHOOK_TOKEN", settings.SOC_WEBHOOK_TOKEN)
    hmac_secret = _setting_or_secret("SOC_WEBHOOK_HMAC_SECRET", settings.SOC_WEBHOOK_HMAC_SECRET)
    ready = url_valid and token and hmac_secret
    return {
        "integration": "soc_webhook",
        "status": _status(ready, degraded=bool(settings.SOC_WEBHOOK_URL)),
        "configured": ready,
        "url_configured": bool(settings.SOC_WEBHOOK_URL),
        "url_valid": url_valid,
        "token_configured": token,
        "hmac_configured": hmac_secret,
        "timeout_seconds": float(settings.SOC_WEBHOOK_TIMEOUT_SEC),
        "contract": "soc_case.v1",
        "secrets_exposed": False,
    }


def build_github_actions_readiness() -> dict[str, Any]:
    token = _setting_or_secret("GITHUB_TOKEN", settings.GITHUB_TOKEN)
    api_valid = _valid_url(settings.GITHUB_API_BASE_URL, require_https=True)
    capability = provider_capability_payload("github_actions")
    ready = token and api_valid
    return {
        "integration": "github_actions",
        "status": _status(ready, degraded=api_valid),
        "configured": ready,
        "api_base_url_valid": api_valid,
        "token_configured": token,
        "default_owner_configured": bool(settings.GITHUB_DEFAULT_OWNER),
        "token_secret_names_configured": bool(settings.GITHUB_TOKEN_SECRET_NAMES.strip()),
        "required_permissions": [
            "repo metadata read",
            "actions environments write",
            "actions artifacts delete",
            "actions secrets delete when revoke_pipeline_token is enabled",
        ],
        "capabilities": capability,
        "secrets_exposed": False,
    }


def build_ingestion_readiness() -> dict[str, Any]:
    adapters = sorted(ADAPTERS)
    sentinel_ready = "sentinel" in ADAPTERS and "microsoft_sentinel" in ADAPTERS
    wazuh_ready = "wazuh" in ADAPTERS
    return {
        "integration": "siem_ingestion",
        "status": _status(sentinel_ready and wazuh_ready),
        "configured": sentinel_ready and wazuh_ready,
        "adapters": adapters,
        "sentinel": {
            "configured": sentinel_ready,
            "aliases": [item for item in ("sentinel", "microsoft_sentinel") if item in ADAPTERS],
            "endpoint": "/api/v1/ingestion/events/sentinel",
        },
        "wazuh": {
            "configured": wazuh_ready,
            "endpoint": "/api/v1/ingestion/events/wazuh",
        },
        "normalizes_to": "ThreatModel",
        "secrets_exposed": False,
    }


def build_secops_integration_readiness(provider: str) -> dict[str, Any]:
    key = provider.strip().lower().replace("-", "_")
    if key == "github_actions":
        return build_github_actions_readiness()
    if key == "redis":
        return build_redis_readiness()
    if key in {"soc_webhook", "generic_webhook"}:
        return build_soc_webhook_readiness()
    if key in {"secret_backend", "secrets"}:
        return build_secret_backend_readiness()
    if key in {"sentinel", "microsoft_sentinel", "wazuh", "siem", "ingestion"}:
        readiness = build_ingestion_readiness()
        readiness["requested_provider"] = key
        return readiness
    return {
        "integration": key,
        "status": "unknown_provider",
        "configured": False,
        "secrets_exposed": False,
    }


def build_all_readiness() -> dict[str, Any]:
    checks = {
        "redis": build_redis_readiness(),
        "github_actions": build_github_actions_readiness(),
        "soc_webhook": build_soc_webhook_readiness(),
        "secret_backend": build_secret_backend_readiness(),
        "siem_ingestion": build_ingestion_readiness(),
    }
    ready = [key for key, value in checks.items() if value.get("status") == "ready"]
    return {
        "module": "secops",
        "phase": "phase-2-integrations-real-readiness",
        "overall": "ready" if len(ready) == len(checks) else "needs_configuration",
        "ready": ready,
        "checks": checks,
        "secrets_exposed": False,
    }


def build_execution_preflight(
    *,
    provider: str,
    action_type: str,
    execution_controls: dict[str, Any],
) -> dict[str, Any]:
    provider_key = provider.strip().lower()
    action_payload = action_preflight_payload(provider_key, action_type)
    controls = execution_controls if isinstance(execution_controls, dict) else {}
    dry_run = bool(controls.get("dry_run", False))
    change_ticket = str(controls.get("change_ticket") or "").strip()
    readiness = build_secops_integration_readiness(provider_key)
    checks = {
        "provider_action_supported": bool(action_payload["supported"]),
        "provider_configured": bool(readiness.get("configured")),
        "dry_run_declared": "dry_run" in controls,
        "change_ticket_present": bool(change_ticket),
    }
    if provider_key == "github_actions" and action_payload["recommended_action"] == "revoke_pipeline_token":
        checks["token_secret_names_configured"] = bool(settings.GITHUB_TOKEN_SECRET_NAMES.strip())
    real_mode = not dry_run
    if real_mode:
        checks["real_mode_change_ticket_required"] = bool(change_ticket)
    allowed = all(checks.values())
    return {
        "provider": action_payload["provider"],
        "action_type": action_payload["action_type"],
        "mode": "dry_run" if dry_run else "real",
        "allowed": allowed,
        "checks": checks,
        "provider_preflight": action_payload,
        "readiness": readiness,
        "reason": "ok" if allowed else "preflight_failed",
        "secrets_exposed": False,
    }
