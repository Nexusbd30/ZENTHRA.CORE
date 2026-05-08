import shutil
import uuid
from pathlib import Path

from app.services.runtime_log_service import list_runtime_logs


def _make_workspace(monkeypatch):
    workspace = Path.cwd() / f".test-runtime-logs-{uuid.uuid4().hex}"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    return workspace


def test_runtime_logs_parse_request_lines_and_filter_by_search(monkeypatch):
    workspace = _make_workspace(monkeypatch)
    log_dir = workspace / "logs"
    log_dir.mkdir()
    try:
        (log_dir / "app.log").write_text(
            "\n".join(
                [
                    "2026-05-09 10:00:00,100 - INFO - zenthra - GET /monitoring/health -> 200 (12.5ms)",
                    "2026-05-09 10:01:00,200 - ERROR - zenthra - POST /auth/login -> 401 (3.2ms)",
                    "not a structured log line",
                ]
            ),
            encoding="utf-8",
        )

        result = list_runtime_logs(limit=10, search="/monitoring")

        assert result["total"] == 1
        assert result["files"] == ["app.log"]
        item = result["items"][0]
        assert item["path"] == "/monitoring/health"
        assert item["request_method"] == "GET"
        assert item["status_code"] == 200
        assert item["duration_ms"] == 12.5
        assert item["protocol"] == "HTTP:MON"
        assert item["action"] == "ALLOWED"
        assert item["severity"] == "low"
        assert item["event_id"].startswith("ZX-")
    finally:
        monkeypatch.chdir(workspace.parent)
        shutil.rmtree(workspace, ignore_errors=True)


def test_runtime_logs_filter_severity_and_include_alert_audit(monkeypatch):
    workspace = _make_workspace(monkeypatch)
    log_dir = workspace / "logs"
    log_dir.mkdir()
    try:
        (log_dir / "app.log").write_text(
            "2026-05-09 10:00:00,100 - INFO - zenthra - GET /health -> 200 (1.0ms)\n",
            encoding="utf-8",
        )
        (log_dir / "alerts_audit.log").write_text(
            "2026-05-09 10:02:00,300 - ERROR - alerts_audit - ALERT_HOOK ip=10.0.0.5 len=12 sha256=abc sample={}\n",
            encoding="utf-8",
        )

        result = list_runtime_logs(limit=10, severity="critical")

        assert result["total"] == 1
        item = result["items"][0]
        assert item["logger"] == "alerts_audit"
        assert item["source_ip"] == "10.0.0.5"
        assert item["protocol"] == "WEBHOOK"
        assert item["action"] == "BLOCKED"
        assert item["severity"] == "critical"
    finally:
        monkeypatch.chdir(workspace.parent)
        shutil.rmtree(workspace, ignore_errors=True)


def test_runtime_logs_reads_rotated_files_and_respects_limit(monkeypatch):
    workspace = _make_workspace(monkeypatch)
    log_dir = workspace / "logs"
    log_dir.mkdir()
    try:
        (log_dir / "app.log.1").write_text(
            "\n".join(
                [
                    "2026-05-09 10:00:00,100 - WARNING - zenthra - GET /threats/ -> 403 (1.0ms)",
                    "2026-05-09 10:01:00,100 - INFO - zenthra - GET /users/me -> 200 (1.0ms)",
                ]
            ),
            encoding="utf-8",
        )

        result = list_runtime_logs(limit=1)

        assert result["total"] == 1
        assert result["items"][0]["path"] == "/users/me"
        assert result["items"][0]["protocol"] == "HTTP:USR"
        assert result["files"] == ["app.log.1"]
    finally:
        monkeypatch.chdir(workspace.parent)
        shutil.rmtree(workspace, ignore_errors=True)
