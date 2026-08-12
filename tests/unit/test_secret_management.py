from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import requests
from jose import jwt

from app.actions._dispatch import dispatch_command
from app.core import secrets
from app.core.internal_auth import require_internal_bearer
from app.core.security import ALGORITHM, create_access_token
from app.core.settings import settings
from app.core.signing import sign_payload, verify_payload_signature
from app.identity.entra import (
    build_entra_provider_evidence,
    build_entra_readiness,
    expected_entra_signature,
    verify_entra_webhook_signature,
)
from app.identity.entra_graph import _graph_config
from app.routers.monitoring import _production_readiness_report
from app.secops.github import _headers
from app.secops.service import send_security_event_export_webhook


def test_file_secret_backend_reads_named_secret(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    secret_file = secret_dir / "GITHUB_TOKEN"
    secret_file.write_text("ghs_test\n", encoding="utf-8")
    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))

    assert secrets.get_secret("GITHUB_TOKEN") == "ghs_test"


def test_file_secret_backend_strips_utf8_bom(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "ZENTHRA_MONITOR_TOKEN").write_text(
        "\ufeffmonitor-token\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))

    assert secrets.get_secret("ZENTHRA_MONITOR_TOKEN") == "monitor-token"


def test_secret_backend_status_never_exposes_values(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "SOC_WEBHOOK_TOKEN").write_text("token-value", encoding="utf-8")
    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))

    status = secrets.secret_backend_status()

    assert status["backend"] == "file"
    assert status["production_ready"] is True
    assert status["configured"]["SOC_WEBHOOK_TOKEN"] is True
    assert "token-value" not in str(status)
    assert status["secrets_exposed"] is False


def test_core_auth_and_signing_read_file_backed_secrets(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "SECRET_KEY").write_text("file-secret-key", encoding="utf-8")
    (secret_dir / "ZENTHRA_MONITOR_TOKEN").write_text("file-monitor-token", encoding="utf-8")

    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))
    monkeypatch.setattr(settings, "SECRET_KEY", "settings-secret-key")
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "")

    require_internal_bearer(authorization="Bearer file-monitor-token")
    token = create_access_token({"sub": "admin@example.com"})
    payload = jwt.decode(token, "file-secret-key", algorithms=[ALGORITHM])
    signature = sign_payload({"event": "test"})

    assert payload["sub"] == "admin@example.com"
    assert verify_payload_signature({"event": "test"}, signature) is True


def test_production_rejects_plain_env_secret_backend(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "SECRET_BACKEND", "env")

    try:
        secrets.validate_production_secret_backend()
    except RuntimeError as exc:
        assert "SECRET_BACKEND" in str(exc)
    else:
        raise AssertionError("production must reject env-only secret backend")


def test_provider_execution_reads_file_backed_secrets(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "GITHUB_TOKEN").write_text("ghs_file_token", encoding="utf-8")
    (secret_dir / "ENTRA_CLIENT_SECRET").write_text("entra-file-secret", encoding="utf-8")
    (secret_dir / "ACTION_SHARED_TOKEN").write_text("shared-file-token", encoding="utf-8")

    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "")
    monkeypatch.setattr(settings, "ENTRA_TENANT_ID", "tenant-id")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_SECRET", "")
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "webhook")
    monkeypatch.setattr(settings, "ACTION_SHARED_TOKEN", "")

    captured = {}

    class FakeResponse:
        content = b'{"status":"ok"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "ok"}

    def fake_post(url, **kwargs):
        captured["headers"] = kwargs["headers"]
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)

    assert _headers()["Authorization"] == "Bearer ghs_file_token"
    assert _graph_config().client_secret == "entra-file-secret"
    assert dispatch_command(url="https://actions.example", command="test", payload={}) == {
        "status": "ok"
    }
    assert captured["headers"]["Authorization"] == "Bearer shared-file-token"


def test_entra_webhook_reads_file_backed_secret(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "ENTRA_CLIENT_SECRET").write_text("entra-file-secret", encoding="utf-8")
    (secret_dir / "ENTRA_WEBHOOK_SECRET").write_text("webhook-file-secret", encoding="utf-8")

    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))
    monkeypatch.setattr(settings, "ENTRA_TENANT_ID", "tenant-id")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "ENTRA_CLIENT_SECRET", "")
    monkeypatch.setattr(settings, "ENTRA_WEBHOOK_SECRET", "")
    monkeypatch.setattr(settings, "ENTRA_GRAPH_ENABLED", True)

    body = b'{"id":"event-1"}'
    timestamp = "1000"
    signature = expected_entra_signature(body, "webhook-file-secret", timestamp)

    assert verify_entra_webhook_signature(body, signature, timestamp) is False
    monkeypatch.setattr("app.identity.entra._timestamp_is_fresh", lambda value: value == timestamp)
    assert verify_entra_webhook_signature(body, signature, timestamp) is True

    readiness = build_entra_readiness()
    evidence = build_entra_provider_evidence(payload={"id": "event-1"}, body=body, timestamp=timestamp)

    assert readiness["graph_credentials_configured"] is True
    assert readiness["webhook_secret_configured"] is True
    assert evidence["signature"]["verified"] is True


def test_monitoring_readiness_reads_file_backed_action_secret(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "ACTION_SHARED_TOKEN").write_text("shared-file-token", encoding="utf-8")

    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "webhook")
    monkeypatch.setattr(settings, "ACTION_SHARED_TOKEN", "")
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(settings, "ALERTMANAGER_ALLOWED_CIDRS", "172.16.0.0/12")

    report = _production_readiness_report()

    assert report["ares"]["shared_token_configured"] is True
    assert "ACTION_SHARED_TOKEN requerido para ejecucion webhook real." not in report["warnings"]


def test_soc_webhook_export_reads_file_backed_secrets(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "SOC_WEBHOOK_TOKEN").write_text("soc-file-token", encoding="utf-8")
    (secret_dir / "SOC_WEBHOOK_HMAC_SECRET").write_text("soc-file-hmac", encoding="utf-8")

    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))
    monkeypatch.setattr(settings, "SOC_WEBHOOK_URL", "https://soc.example/hook")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_TOKEN", "")
    monkeypatch.setattr(settings, "SOC_WEBHOOK_HMAC_SECRET", "")

    captured = {}

    class FakeResponse:
        status_code = 202

        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)

    result = send_security_event_export_webhook({"contract": "soc_case.v1", "items": []})

    assert result["status"] == "sent"
    assert captured["url"] == "https://soc.example/hook"
    assert captured["headers"]["Authorization"] == "Bearer soc-file-token"
    assert captured["headers"]["X-Zenthra-Signature"].startswith("sha256=")
    assert result["signature"]["enabled"] is True
