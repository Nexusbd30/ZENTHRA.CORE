from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

PLACEHOLDER_MARKERS = (
    "CHANGE_ME",
    "SET_IN_SECRET_MANAGER",
    "SET_IN_GITHUB_ENVIRONMENT",
    "REPLACE_IN_CLUSTER_SECRET_MANAGER",
    "example.com",
    "example.internal",
)

REQUIRED_VALUES = (
    "ENV",
    "PREPRODUCTION_HOSTNAME",
    "POSTGRES_HOST",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "REDIS_URL",
    "CORS_ORIGINS",
    "SECRET_BACKEND",
    "SECRET_FILE_DIR",
    "VAELQORIX_PUBLIC_REGISTRATION_ENABLED",
    "ENTERPRISE_TENANT_MODE",
    "RATE_LIMIT_BACKEND",
    "REPLAY_GUARD_BACKEND",
    "ARES_KILL_SWITCH_BACKEND",
    "ACTION_EXECUTION_MODE",
    "AI_PROVIDER",
    "AI_BASE_URL",
    "AI_MODEL",
    "VECTOR_STORE_PROVIDER",
)

REQUIRED_SECRET_NAMES = (
    "SECRET_KEY",
    "VAELQORIX_MONITOR_TOKEN",
    "POSTGRES_PASSWORD",
    "ACTION_SHARED_TOKEN",
)

OPTIONAL_INTEGRATION_GROUPS = {
    "identity": ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"),
    "devsecops": ("GITHUB_TOKEN", "GITHUB_DEFAULT_OWNER", "GITHUB_TOKEN_SECRET_NAMES"),
    "soc": ("SOC_WEBHOOK_URL", "SOC_WEBHOOK_TOKEN", "SOC_WEBHOOK_HMAC_SECRET"),
}


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    return key.strip(), value.strip().strip("'\"")


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed:
            values[parsed[0]] = parsed[1]
    return values


def merged_environment(env_file: Path | None) -> dict[str, str]:
    values = dict(os.environ)
    if env_file:
        values.update(load_env_file(env_file))
    return values


def _has_placeholder(value: str) -> bool:
    return any(marker.lower() in value.lower() for marker in PLACEHOLDER_MARKERS)


def _is_local_host(value: str) -> bool:
    host = urlparse(value).hostname if "://" in value else value.split(":", 1)[0]
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "postgres", "redis", "ollama"}


def _valid_json_list(value: str) -> bool:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, list) and all(isinstance(item, str) for item in parsed)


def validate(
    values: dict[str, str],
    *,
    allow_placeholders: bool = False,
    cluster_secrets_mounted: bool = False,
) -> list[str]:
    findings: list[str] = []

    for name in REQUIRED_VALUES:
        if not values.get(name):
            findings.append(f"{name} is required for preproduction")

    if not cluster_secrets_mounted:
        for name in REQUIRED_SECRET_NAMES:
            if not values.get(name):
                findings.append(f"{name} must exist in the preproduction secret source")

    for name, value in sorted(values.items()):
        if value and _has_placeholder(value) and not allow_placeholders:
            findings.append(f"{name} still contains a placeholder value")

    exact_values = {
        "ENV": "production",
        "SECRET_BACKEND": "file",
        "VAELQORIX_PUBLIC_REGISTRATION_ENABLED": "false",
        "ENTERPRISE_TENANT_MODE": "strict",
        "RATE_LIMIT_BACKEND": "redis",
        "REPLAY_GUARD_BACKEND": "redis",
        "ARES_KILL_SWITCH_BACKEND": "redis",
    }
    for name, expected in exact_values.items():
        if values.get(name, "").strip().lower() != expected:
            findings.append(f"{name} must be {expected} in preproduction")

    if values.get("SQLALCHEMY_DATABASE_URI", "").startswith("sqlite"):
        findings.append("SQLALCHEMY_DATABASE_URI must not use sqlite in preproduction")

    external_endpoints = (
        "PREPRODUCTION_HOSTNAME",
        "POSTGRES_HOST",
        "REDIS_URL",
        "AI_BASE_URL",
        "PROMETHEUS_BASE",
        "ALERTMANAGER_BASE",
    )
    for name in external_endpoints:
        value = values.get(name, "")
        if value and _is_local_host(value):
            findings.append(f"{name} must point to managed/external infrastructure")

    cors = values.get("CORS_ORIGINS", "")
    if cors:
        if not _valid_json_list(cors):
            findings.append("CORS_ORIGINS must be a JSON list")
        if re.search(r"localhost|127\.0\.0\.1|http://", cors, flags=re.IGNORECASE):
            findings.append("CORS_ORIGINS must contain only HTTPS preproduction origins")

    action_mode = values.get("ACTION_EXECUTION_MODE", "").lower()
    if action_mode not in {"webhook", "provider", "real"}:
        findings.append("ACTION_EXECUTION_MODE must be webhook, provider, or real")

    if values.get("AI_PROVIDER", "").lower() == "local_stub":
        findings.append("AI_PROVIDER must not be local_stub in preproduction")
    if values.get("VECTOR_STORE_PROVIDER", "").lower() == "local":
        findings.append("VECTOR_STORE_PROVIDER must not be local in preproduction")

    ready_groups = [
        group
        for group, required in OPTIONAL_INTEGRATION_GROUPS.items()
        if all(values.get(name) and not _has_placeholder(values[name]) for name in required)
    ]
    if not ready_groups and not allow_placeholders and not cluster_secrets_mounted:
        findings.append("at least one pilot integration group must be fully configured")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate advanced preproduction configuration.")
    parser.add_argument("--env-file", type=Path, help="Optional env file to validate.")
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Allow placeholders when validating committed example files.",
    )
    parser.add_argument(
        "--cluster-secrets-mounted",
        action="store_true",
        help="Trust the cluster secret existence check for sensitive values.",
    )
    args = parser.parse_args()

    env_file = args.env_file
    if env_file and not env_file.is_absolute():
        env_file = ROOT / env_file

    findings = validate(
        merged_environment(env_file),
        allow_placeholders=args.allow_placeholders,
        cluster_secrets_mounted=args.cluster_secrets_mounted,
    )
    if findings:
        print("preproduction readiness failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("preproduction readiness passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
