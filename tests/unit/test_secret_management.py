from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from app.core import secrets
from app.core.settings import settings


def test_file_secret_backend_reads_named_secret(monkeypatch):
    secret_dir = Path(".test-data") / f"secrets-{uuid4()}"
    secret_dir.mkdir(parents=True, exist_ok=True)
    secret_file = secret_dir / "GITHUB_TOKEN"
    secret_file.write_text("ghs_test\n", encoding="utf-8")
    monkeypatch.setattr(settings, "SECRET_BACKEND", "file")
    monkeypatch.setattr(settings, "SECRET_FILE_DIR", str(secret_dir))

    assert secrets.get_secret("GITHUB_TOKEN") == "ghs_test"


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


def test_production_rejects_plain_env_secret_backend(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "SECRET_BACKEND", "env")

    try:
        secrets.validate_production_secret_backend()
    except RuntimeError as exc:
        assert "SECRET_BACKEND" in str(exc)
    else:
        raise AssertionError("production must reject env-only secret backend")
