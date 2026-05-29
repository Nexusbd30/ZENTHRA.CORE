from __future__ import annotations

import os
from pathlib import Path

from app.core.settings import settings

SENSITIVE_SETTING_NAMES = {
    "SECRET_KEY",
    "ZENTHRA_MONITOR_TOKEN",
    "POSTGRES_PASSWORD",
    "ENTRA_CLIENT_SECRET",
    "ENTRA_WEBHOOK_SECRET",
    "ACTION_SHARED_TOKEN",
    "SOC_WEBHOOK_TOKEN",
    "SOC_WEBHOOK_HMAC_SECRET",
    "GITHUB_TOKEN",
}


def get_secret(name: str, default: str | None = None) -> str | None:
    normalized = name.strip()
    backend = str(settings.SECRET_BACKEND or "env").strip().lower()
    if backend == "file":
        candidate = Path(settings.SECRET_FILE_DIR) / normalized
        if candidate.exists() and candidate.is_file():
            return candidate.read_text(encoding="utf-8").strip()
    return os.environ.get(normalized, default)


def secret_backend_status() -> dict[str, object]:
    backend = str(settings.SECRET_BACKEND or "env").strip().lower()
    configured = {
        name: bool(get_secret(name))
        for name in sorted(SENSITIVE_SETTING_NAMES)
    }
    return {
        "backend": backend,
        "file_dir": settings.SECRET_FILE_DIR if backend == "file" else "",
        "production_ready": backend != "env",
        "configured": configured,
        "missing": [name for name, present in configured.items() if not present],
        "secrets_exposed": False,
    }


def validate_production_secret_backend() -> None:
    env = str(settings.ENV or "").strip().lower()
    if env not in {"production", "prod"}:
        return
    backend = str(settings.SECRET_BACKEND or "env").strip().lower()
    if backend == "env":
        raise RuntimeError("SECRET_BACKEND=file or managed secret backend is required in production")
