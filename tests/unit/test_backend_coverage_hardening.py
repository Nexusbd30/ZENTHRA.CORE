from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request

from app.actions import _dispatch
from app.actions.base import BaseAction
from app.actions.crypto import CryptoAction
from app.actions.endpoint import EndpointAction
from app.actions.network import NetworkAction
from app.actions.soar import SoarAction
from app.core import bootstrap_admin as bootstrap_module
from app.core.bootstrap_admin import bootstrap_admin
from app.core.dependencies import get_actor, get_db_session, get_request_id
from app.core.errors import DomainError, register_error_handlers
from app.core.internal_auth import require_internal_bearer
from app.core.logging import configure_logging
from app.core.settings import settings
from app.ingestion.adapters import edr, iam, netflow, qradar
from app.models.user import User
from app.services.network_monitor import NetworkMonitor


def test_bootstrap_admin_is_disabled_by_default(db_session, monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "settings",
        SimpleNamespace(BOOTSTRAP_ADMIN_ENABLED=False),
    )

    bootstrap_admin(db_session)

    assert db_session.query(User).filter_by(email="disabled-admin@example.com").first() is None


def test_bootstrap_admin_requires_password(db_session, monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "settings",
        SimpleNamespace(
            BOOTSTRAP_ADMIN_ENABLED=True,
            BOOTSTRAP_ADMIN_EMAIL=" MissingPassword@Example.com ",
            BOOTSTRAP_ADMIN_PASSWORD=None,
        ),
    )

    bootstrap_admin(db_session)

    assert db_session.query(User).filter_by(email="missingpassword@example.com").first() is None


def test_bootstrap_admin_creates_and_promotes_idempotently(db_session, monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "settings",
        SimpleNamespace(
            BOOTSTRAP_ADMIN_ENABLED=True,
            BOOTSTRAP_ADMIN_EMAIL=" CoverageAdmin@Example.com ",
            BOOTSTRAP_ADMIN_PASSWORD="strong-password",
        ),
    )

    bootstrap_admin(db_session)
    created = db_session.query(User).filter_by(email="coverageadmin@example.com").first()

    assert created is not None
    assert created.role == "admin"
    assert created.hashed_password != "strong-password"

    created.role = "user"
    db_session.add(created)
    db_session.commit()

    bootstrap_admin(db_session)

    promoted = db_session.query(User).filter_by(email="coverageadmin@example.com").first()
    assert promoted.role == "admin"
    assert db_session.query(User).filter_by(email="coverageadmin@example.com").count() == 1


def test_action_dispatch_mock_and_provider_modes(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    mock_result = _dispatch.dispatch_command(
        url=None,
        command="network_isolate",
        payload={"target": "host-1"},
    )
    assert mock_result["status"] == "ok"
    assert mock_result["mode"] == "mock"

    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "real")
    monkeypatch.setattr(settings, "ENTRA_GRAPH_ENABLED", True)
    monkeypatch.setattr(
        _dispatch,
        "dispatch_entra_graph_command",
        lambda **kwargs: {"status": "entra", **kwargs},
    )
    entra_result = _dispatch.dispatch_command(
        url=None,
        command="identity.revoke_session",
        payload={"provider": "entra"},
    )
    assert entra_result["status"] == "entra"

    monkeypatch.setattr(
        _dispatch,
        "dispatch_github_command",
        lambda **kwargs: {"status": "github", **kwargs},
    )
    github_result = _dispatch.dispatch_command(
        url=None,
        command="devsecops.block_deployment",
        payload={"provider": "github_actions"},
    )
    assert github_result["status"] == "github"


def test_action_dispatch_webhook_modes(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "webhook")
    monkeypatch.setattr(settings, "ACTION_SHARED_TOKEN", "action-token")
    monkeypatch.setattr(settings, "ACTION_TIMEOUT_SEC", 3.0)

    with pytest.raises(RuntimeError, match="Webhook URL not configured"):
        _dispatch.dispatch_command(url=None, command="observe", payload={})

    calls = []

    class JsonResponse:
        content = b'{"status":"ok"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "remote-ok"}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return JsonResponse()

    monkeypatch.setattr(_dispatch.requests, "post", fake_post)

    result = _dispatch.dispatch_command(
        url="https://actions.example/execute",
        command="observe",
        payload={"target": "host-1"},
    )

    assert result == {"status": "remote-ok"}
    assert calls[0][0] == "https://actions.example/execute"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer action-token"
    assert calls[0][1]["headers"]["X-Idempotency-Key"]

    class EmptyResponse:
        content = b""

        def raise_for_status(self):
            return None

    monkeypatch.setattr(_dispatch.requests, "post", lambda *args, **kwargs: EmptyResponse())
    assert _dispatch.dispatch_command(
        url="https://actions.example/execute",
        command="observe",
        payload={},
    ) == {"status": "ok", "command": "observe"}


def test_action_dispatch_rejects_unknown_mode(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "invalid")

    with pytest.raises(RuntimeError, match="Unsupported ACTION_EXECUTION_MODE"):
        _dispatch.dispatch_command(url=None, command="observe", payload={})


def test_ingestion_adapters_cover_default_and_severity_branches():
    edr_event = edr.adapt_edr_event({"alert": {"id": "d1", "severity": "high"}})
    assert edr_event["fingerprint"] == "edr|d1|unknown-endpoint"
    assert edr_event["labels"]["job"] == "edr"

    iam_event = iam.adapt_iam_event({"actor": {"email": "alice@example.com", "ip": "10.0.0.1"}})
    assert iam_event["target"] == "alice@example.com"
    assert iam_event["source_ip"] == "10.0.0.1"

    assert netflow._severity_from_bytes("bad") == "medium"
    assert netflow._severity_from_bytes(20_000_000_000) == "critical"
    assert netflow._severity_from_bytes(2_000_000_000) == "high"
    assert netflow._severity_from_bytes(200_000_000) == "medium"
    assert netflow._severity_from_bytes(10) == "low"
    flow = netflow.adapt_netflow_event(
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "203.0.113.5", "port": 443},
            "network": {"bytes": 200_000_000, "protocol": "tcp"},
        }
    )
    assert flow["severity"] == "medium"
    assert flow["target"] == "203.0.113.5"

    assert qradar._severity_from_qradar("not-a-number") == "not-a-number"
    assert qradar._severity_from_qradar(9) == "critical"
    assert qradar._severity_from_qradar(6) == "high"
    assert qradar._severity_from_qradar(3) == "medium"
    assert qradar._severity_from_qradar(1) == "low"
    offense = qradar.adapt_qradar_event({"id": "off-1", "magnitude": 8})
    assert offense["severity"] == "critical"
    assert offense["labels"]["offense_id"] == "off-1"


def test_network_monitor_start_stop_and_post_paths(monkeypatch):
    started = []
    joined = []

    class FakeThread:
        def __init__(self, *, target, daemon):
            self.target = target
            self.daemon = daemon

        def start(self):
            started.append(self.daemon)

        def join(self):
            joined.append(True)

    monkeypatch.setattr("app.services.network_monitor.threading.Thread", FakeThread)

    monitor = NetworkMonitor("https://api.example/", "token", check_interval=1, simulate=True)
    monitor.start()
    monitor.start()
    monitor.stop()

    assert started == [True]
    assert joined == [True]

    calls = []

    class CreatedResponse:
        status_code = 201
        text = "created"

    monkeypatch.setattr(
        "app.services.network_monitor.requests.post",
        lambda *args, **kwargs: calls.append((args, kwargs)) or CreatedResponse(),
    )
    monitor._post_threat({"title": "Threat", "level": "medium"})
    assert calls[0][0][0] == "https://api.example/threats/"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer token"

    class ErrorResponse:
        status_code = 500
        text = "error"

    monkeypatch.setattr(
        "app.services.network_monitor.requests.post",
        lambda *args, **kwargs: ErrorResponse(),
    )
    monitor._post_threat({"title": "Threat", "level": "medium"})

    def failing_post(*args, **kwargs):
        raise RuntimeError("offline")

    monkeypatch.setattr("app.services.network_monitor.requests.post", failing_post)
    monitor._post_threat({"title": "Threat", "level": "medium"})

    reported = []
    monkeypatch.setattr(monitor, "_post_threat", lambda payload: reported.append(payload))
    monitor._report_real_threat(12_000_000, 2_000_000)
    assert reported[0]["source"] == "NetworkMonitor (psutil)"


def test_simple_actions_delegate_and_rollback(monkeypatch):
    calls = []

    def fake_dispatch(*, url, command, payload):
        calls.append({"url": url, "command": command, "payload": payload})
        return {"status": "ok", "command": command}

    monkeypatch.setattr("app.actions.crypto.dispatch_command", fake_dispatch)
    monkeypatch.setattr("app.actions.endpoint.dispatch_command", fake_dispatch)
    monkeypatch.setattr("app.actions.network.dispatch_command", fake_dispatch)
    monkeypatch.setattr("app.actions.soar.dispatch_command", fake_dispatch)

    step = {"step": "isolate", "payload": {"target": "host-1"}}
    controls = {
        "change_ticket": "CHG-1",
        "threat_id": "threat-1",
        "key_id": "key-1",
        "secret_ref": "secret-1",
        "reason": "test",
    }

    for action in (CryptoAction(), EndpointAction(), NetworkAction(), SoarAction()):
        result = action.execute_step(step, controls)
        rollback = action.rollback_step(result.rollback_payload or {})
        assert result.status == "ok"
        assert rollback.status == "ok"

    assert {call["command"] for call in calls} >= {
        "isolate",
        "crypto_rotation_rollback",
        "endpoint_rollback",
        "network_rollback",
        "close_or_annotate_case",
    }


def test_base_action_requires_implementation():
    action = BaseAction()

    with pytest.raises(NotImplementedError):
        action.execute_step({}, {})
    with pytest.raises(NotImplementedError):
        action.rollback_step({})


def test_core_dependency_and_internal_auth_helpers(monkeypatch):
    db = object()
    assert get_db_session(db) is db

    actor = object()
    assert get_actor(actor) is actor

    request = SimpleNamespace(headers={"x-request-id": "req-header"})
    assert get_request_id(request, x_request_id=None) == "req-header"
    assert get_request_id(request, x_request_id="req-explicit") == "req-explicit"
    assert get_request_id(SimpleNamespace(headers={}), x_request_id=None) == "n/a"

    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", None)
    with pytest.raises(HTTPException) as missing:
        require_internal_bearer(None)
    assert missing.value.status_code == 503

    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "token")
    with pytest.raises(HTTPException) as malformed:
        require_internal_bearer("token")
    assert malformed.value.status_code == 401

    with pytest.raises(HTTPException) as forbidden:
        require_internal_bearer("Bearer bad")
    assert forbidden.value.status_code == 403

    assert require_internal_bearer("Bearer token") is None


@pytest.mark.asyncio
async def test_error_handlers_return_normalized_payloads():
    app = FastAPI()
    register_error_handlers(app)

    domain_handler = app.exception_handlers[DomainError]
    domain_response = await domain_handler(
        Request({"type": "http", "method": "GET", "path": "/", "headers": []}),
        DomainError("domain_code", "domain message", status_code=409),
    )
    assert domain_response.status_code == 409
    assert b"domain_code" in domain_response.body

    http_handler = app.exception_handlers[HTTPException]
    http_response = await http_handler(
        Request({"type": "http", "method": "GET", "path": "/", "headers": []}),
        HTTPException(status_code=418, detail="teapot", headers={"X-Test": "1"}),
    )
    assert http_response.status_code == 418
    assert http_response.headers["x-test"] == "1"
    assert b"http_error" in http_response.body


def test_configure_logging_is_idempotent(monkeypatch):
    logger = configure_logging()
    try:
        assert logger.name == "aresx"
        assert len(logger.handlers) >= 2
        assert configure_logging() is logger
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
