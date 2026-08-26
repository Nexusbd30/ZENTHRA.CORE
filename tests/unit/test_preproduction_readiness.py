from __future__ import annotations

from scripts.preproduction_readiness import validate


def _valid_config() -> dict[str, str]:
    return {
        "ENV": "production",
        "PREPRODUCTION_HOSTNAME": "preproduc.vaelqorix.io",
        "POSTGRES_HOST": "pg-preproduc.private.vaelqorix.io",
        "POSTGRES_DB": "vaelqorix_preproduc",
        "POSTGRES_USER": "vaelqorix",
        "POSTGRES_PASSWORD": "managed-secret",
        "REDIS_URL": "rediss://redis-preproduc.private.vaelqorix.io:6380/0",
        "CORS_ORIGINS": '["https://preproduc.vaelqorix.io"]',
        "SECRET_BACKEND": "file",
        "SECRET_FILE_DIR": "/run/secrets/aresx",
        "SECRET_KEY": "managed-secret",
        "VAELQORIX_MONITOR_TOKEN": "managed-secret",
        "ACTION_SHARED_TOKEN": "managed-secret",
        "VAELQORIX_PUBLIC_REGISTRATION_ENABLED": "false",
        "ENTERPRISE_TENANT_MODE": "strict",
        "RATE_LIMIT_BACKEND": "redis",
        "REPLAY_GUARD_BACKEND": "redis",
        "ARES_KILL_SWITCH_BACKEND": "redis",
        "ACTION_EXECUTION_MODE": "webhook",
        "AI_PROVIDER": "azure_openai",
        "AI_BASE_URL": "https://ai-gateway.vaelqorix.io",
        "AI_MODEL": "gpt-5-mini",
        "VECTOR_STORE_PROVIDER": "qdrant",
        "ENTRA_TENANT_ID": "tenant",
        "ENTRA_CLIENT_ID": "client",
        "ENTRA_CLIENT_SECRET": "managed-secret",
    }


def test_preproduction_readiness_accepts_managed_external_config():
    assert validate(_valid_config()) == []


def test_preproduction_readiness_rejects_lab_defaults():
    config = _valid_config()
    config.update(
        {
            "POSTGRES_HOST": "localhost",
            "REDIS_URL": "redis://127.0.0.1:6379/0",
            "CORS_ORIGINS": '["http://localhost:5173"]',
            "ACTION_EXECUTION_MODE": "mock",
            "VECTOR_STORE_PROVIDER": "local",
        }
    )

    findings = validate(config)

    assert any("POSTGRES_HOST" in finding for finding in findings)
    assert any("REDIS_URL" in finding for finding in findings)
    assert any("CORS_ORIGINS" in finding for finding in findings)
    assert any("ACTION_EXECUTION_MODE" in finding for finding in findings)
    assert any("VECTOR_STORE_PROVIDER" in finding for finding in findings)


def test_preproduction_readiness_rejects_placeholders_for_real_runs():
    config = _valid_config()
    config["SECRET_KEY"] = "SET_IN_SECRET_MANAGER"

    findings = validate(config)

    assert "SECRET_KEY still contains a placeholder value" in findings


def test_preproduction_readiness_allows_cluster_secret_validation_mode():
    config = _valid_config()
    for name in (
        "SECRET_KEY",
        "VAELQORIX_MONITOR_TOKEN",
        "POSTGRES_PASSWORD",
        "ACTION_SHARED_TOKEN",
        "ENTRA_TENANT_ID",
        "ENTRA_CLIENT_ID",
        "ENTRA_CLIENT_SECRET",
    ):
        config.pop(name)

    assert validate(config, cluster_secrets_mounted=True) == []
