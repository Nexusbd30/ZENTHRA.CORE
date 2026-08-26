from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import requests

from app.core.secrets import get_secret
from app.core.settings import settings

GITHUB_COMMANDS = {
    "devsecops.resolve_pipeline",
    "devsecops.require_release_approval",
    "devsecops.revoke_pipeline_token",
    "devsecops.quarantine_artifact",
    "devsecops.block_deployment",
}


def _compact(value: Any) -> str:
    return str(value or "").strip()


def _configured_secret_names() -> list[str]:
    return [item.strip() for item in settings.GITHUB_TOKEN_SECRET_NAMES.split(",") if item.strip()]


def _repo(payload: dict[str, Any]) -> str:
    raw_pipeline = payload.get("pipeline")
    pipeline = raw_pipeline if isinstance(raw_pipeline, dict) else {}
    raw_repo = _compact(pipeline.get("repository") or payload.get("target"))
    if raw_repo.startswith("repository:"):
        raw_repo = raw_repo.removeprefix("repository:")
    if not raw_repo:
        raise RuntimeError("GitHub repository must be provided as owner/repo")
    if "/" not in raw_repo and settings.GITHUB_DEFAULT_OWNER:
        raw_repo = f"{settings.GITHUB_DEFAULT_OWNER}/{raw_repo}"
    if "/" not in raw_repo:
        raise RuntimeError("GitHub repository must be provided as owner/repo")
    return raw_repo


def _headers() -> dict[str, str]:
    token = get_secret("GITHUB_TOKEN", settings.GITHUB_TOKEN)
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required for GitHub provider execution")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _url(path: str) -> str:
    return f"{settings.GITHUB_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"


def _evidence(
    *,
    command: str,
    repository: str,
    operation: str,
    api_path: str,
    status_code: int,
    provider_request_id: str | None,
) -> dict[str, Any]:
    return {
        "kind": "devsecops_provider_github_action",
        "provider": "github_actions",
        "command": command,
        "operation": operation,
        "api_path": api_path,
        "http_status": status_code,
        "provider_request_id": provider_request_id or str(uuid4()),
        "repository_sha256": hashlib.sha256(repository.lower().encode("utf-8")).hexdigest(),
        "recorded_at": datetime.now(UTC).isoformat(),
        "secrets_exposed": False,
    }


def _repo_path(repository: str) -> str:
    owner, repo = repository.split("/", 1)
    return f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}"


def dispatch_github_command(*, command: str, payload: dict[str, Any]) -> dict[str, Any]:
    if command not in GITHUB_COMMANDS:
        raise RuntimeError(f"Unsupported GitHub command: {command}")

    headers = _headers()
    repository = _repo(payload)
    repo_path = _repo_path(repository)
    raw_pipeline = payload.get("pipeline")
    pipeline = raw_pipeline if isinstance(raw_pipeline, dict) else {}
    environment = _compact(pipeline.get("environment") or "production")

    if command == "devsecops.resolve_pipeline":
        response = requests.get(_url(repo_path), headers=headers, timeout=float(settings.ACTION_TIMEOUT_SEC))
        response.raise_for_status()
        body = response.json()
        return {
            "mode": "github_api",
            "command": command,
            "status": "ok",
            "provider": "github_actions",
            "repository": repository,
            "visibility": body.get("visibility"),
            "default_branch": body.get("default_branch"),
            "provider_evidence": _evidence(
                command=command,
                repository=repository,
                operation="resolve_repository",
                api_path=repo_path,
                status_code=response.status_code,
                provider_request_id=response.headers.get("x-github-request-id"),
            ),
        }

    if command in {"devsecops.require_release_approval", "devsecops.block_deployment"}:
        path = f"{repo_path}/environments/{quote(environment, safe='')}"
        response = requests.put(
            _url(path),
            headers=headers,
            json={"prevent_self_review": True, "wait_timer": 0},
            timeout=float(settings.ACTION_TIMEOUT_SEC),
        )
        response.raise_for_status()
        return {
            "mode": "github_api",
            "command": command,
            "status": "ok",
            "provider": "github_actions",
            "repository": repository,
            "environment": environment,
            "operation": "environment_protection_gate",
            "provider_evidence": _evidence(
                command=command,
                repository=repository,
                operation="environment_protection_gate",
                api_path=path,
                status_code=response.status_code,
                provider_request_id=response.headers.get("x-github-request-id"),
            ),
        }

    if command == "devsecops.quarantine_artifact":
        raw_finding = payload.get("finding")
        finding = raw_finding if isinstance(raw_finding, dict) else {}
        artifact_id = _compact(finding.get("artifact_id") or pipeline.get("artifact_id"))
        if not artifact_id:
            raise RuntimeError("GitHub artifact_id is required for quarantine_artifact")
        path = f"{repo_path}/actions/artifacts/{quote(artifact_id, safe='')}"
        response = requests.delete(
            _url(path),
            headers=headers,
            timeout=float(settings.ACTION_TIMEOUT_SEC),
        )
        if response.status_code not in {204, 404}:
            response.raise_for_status()
        return {
            "mode": "github_api",
            "command": command,
            "status": "ok",
            "provider": "github_actions",
            "repository": repository,
            "artifact_id": artifact_id,
            "operation": "delete_actions_artifact",
            "provider_evidence": _evidence(
                command=command,
                repository=repository,
                operation="delete_actions_artifact",
                api_path=path,
                status_code=response.status_code,
                provider_request_id=response.headers.get("x-github-request-id"),
            ),
        }

    secret_names = _configured_secret_names()
    if not secret_names:
        raise RuntimeError("GITHUB_TOKEN_SECRET_NAMES is required for revoke_pipeline_token")
    revoked = []
    for secret_name in secret_names:
        path = f"{repo_path}/actions/secrets/{quote(secret_name, safe='')}"
        response = requests.delete(
            _url(path),
            headers=headers,
            timeout=float(settings.ACTION_TIMEOUT_SEC),
        )
        if response.status_code not in {204, 404}:
            response.raise_for_status()
        revoked.append(secret_name)
    return {
        "mode": "github_api",
        "command": command,
        "status": "ok",
        "provider": "github_actions",
        "repository": repository,
        "operation": "delete_actions_secrets",
        "secret_names": revoked,
        "provider_evidence": {
            "kind": "devsecops_provider_github_action_batch",
            "provider": "github_actions",
            "command": command,
            "secret_count": len(revoked),
            "secrets_exposed": False,
        },
    }
