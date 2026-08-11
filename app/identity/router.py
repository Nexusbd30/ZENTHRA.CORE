from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.observability.metrics import record_security_webhook_rejection
from app.core.rate_limit import check_rate_limit
from app.core.replay_guard import check_replay
from app.core.secrets import get_secret
from app.core.security import require_admin_or_monitor_token, require_enterprise_capability
from app.core.settings import settings
from app.db.audit_store import append_audit_record
from app.db.session import get_db
from app.identity.contracts import (
    IdentityActionPreflightRequest,
    IdentityActionPreflightResponse,
    IdentityActivityResponse,
    IdentityEventTimelineResponse,
    IdentityLifecycleRequest,
    IdentityProviderCapabilityRead,
    IdentityProviderListResponse,
    IdentitySignal,
    IdentityTriageRequest,
)
from app.identity.entra import (
    build_entra_provider_evidence,
    build_entra_readiness,
    entra_replay_key,
    normalize_entra_risk_event,
    verify_entra_webhook_signature,
)
from app.identity.providers import (
    action_preflight_payload,
    list_provider_capability_payloads,
    provider_capability_payload,
)
from app.identity.service import (
    list_identity_event_timeline,
    persist_identity_event,
    summarize_identity_activity,
)
from app.models.threat_event import ThreatEvent
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/identity",
    tags=["identity-defense"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


def _response(event: ThreatEvent, *, duplicate: bool, elapsed_ms: float) -> dict[str, Any]:
    return {
        "status": "accepted",
        "event_id": event.id,
        "source_event_id": event.event_id,
        "source": event.source,
        "event_type": event.event_type,
        "entity_id": event.entity_id,
        "entity_type": event.entity_type,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "mitre_tags": json.loads(event.mitre_tags or "[]"),
        "is_duplicate": duplicate,
        "processing_time_ms": round(elapsed_ms, 2),
    }


@router.get("/providers", response_model=IdentityProviderListResponse)
def list_identity_providers():
    return {"providers": list_provider_capability_payloads()}


@router.get("/providers/{provider}", response_model=IdentityProviderCapabilityRead)
def read_identity_provider(provider: str):
    try:
        return provider_capability_payload(provider)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/providers/entra/readiness")
def read_entra_readiness():
    return build_entra_readiness()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def _audit_entra_security_rejection(
    db: Session,
    *,
    request: Request,
    body: bytes,
    payload: dict[str, Any],
    enterprise_context: dict[str, Any],
    reason: str,
    status_code: int,
) -> None:
    record_security_webhook_rejection(provider="entra", reason=reason, status_code=status_code)
    append_audit_record(
        db,
        verdict_id="identity:entra:webhook",
        actor=str(enterprise_context.get("actor") or "system"),
        actor_role=str(enterprise_context.get("role") or "system"),
        tenant_id=str(enterprise_context.get("tenant_id") or settings.DEFAULT_TENANT_ID),
        capability=str(enterprise_context.get("capability") or "identity:triage"),
        request_id=str(enterprise_context.get("request_id") or "n/a"),
        action="identity_entra_webhook_rejected",
        result={
            "status": "rejected",
            "reason": reason,
            "status_code": status_code,
            "provider": "entra",
            "source": "identity:entra",
            "source_event_id": str(payload.get("id") or payload.get("event_id") or ""),
            "client_ip": _client_ip(request),
            "payload_sha256": hashlib.sha256(body).hexdigest(),
            "secrets_exposed": False,
        },
    )


def _enforce_entra_rate_limit(
    db: Session,
    *,
    request: Request,
    body: bytes,
    payload: dict[str, Any],
    enterprise_context: dict[str, Any],
) -> None:
    if not settings.ENTRA_WEBHOOK_RATE_LIMIT_ENABLED:
        return
    tenant_id = str(enterprise_context.get("tenant_id") or settings.DEFAULT_TENANT_ID)
    key = f"identity:entra:{tenant_id}:{_client_ip(request)}"
    decision = check_rate_limit(
        key=key,
        limit=settings.ENTRA_WEBHOOK_RATE_LIMIT_REQUESTS,
        window_seconds=settings.ENTRA_WEBHOOK_RATE_LIMIT_WINDOW_SEC,
    )
    if not decision.allowed:
        _audit_entra_security_rejection(
            db,
            request=request,
            body=body,
            payload=payload,
            enterprise_context=enterprise_context,
            reason="rate_limit_exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Entra webhook rate limit exceeded",
            headers={
                "Retry-After": str(decision.retry_after_seconds),
                "X-RateLimit-Limit": str(decision.limit),
                "X-RateLimit-Remaining": str(decision.remaining),
            },
        )


def _enforce_entra_replay_guard(
    db: Session,
    *,
    request: Request,
    body: bytes,
    payload: dict[str, Any],
    signature: str | None,
    timestamp: str | None,
    enterprise_context: dict[str, Any],
) -> None:
    webhook_secret = get_secret("ENTRA_WEBHOOK_SECRET", settings.ENTRA_WEBHOOK_SECRET)
    if not settings.ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED or not webhook_secret:
        return
    decision = check_replay(
        key=entra_replay_key(body=body, signature=signature, timestamp=timestamp),
        ttl_seconds=settings.ENTRA_WEBHOOK_REPLAY_TTL_SEC,
    )
    if not decision.accepted:
        _audit_entra_security_rejection(
            db,
            request=request,
            body=body,
            payload=payload,
            enterprise_context=enterprise_context,
            reason="replay_detected",
            status_code=status.HTTP_409_CONFLICT,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Entra webhook replay detected",
        )


@router.post("/providers/entra/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_entra_event(
    request: Request,
    payload: dict[str, Any],
    x_zenthra_signature: str | None = Header(default=None),
    x_zenthra_timestamp: str | None = Header(default=None),
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("identity:triage")),
):
    _ = enterprise_context
    start = time.perf_counter()
    body = await request.body()
    _enforce_entra_rate_limit(
        db,
        request=request,
        body=body,
        payload=payload,
        enterprise_context=enterprise_context,
    )
    if not verify_entra_webhook_signature(body, x_zenthra_signature, x_zenthra_timestamp):
        _audit_entra_security_rejection(
            db,
            request=request,
            body=body,
            payload=payload,
            enterprise_context=enterprise_context,
            reason="invalid_signature",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Entra webhook signature",
        )
    _enforce_entra_replay_guard(
        db,
        request=request,
        body=body,
        payload=payload,
        signature=x_zenthra_signature,
        timestamp=x_zenthra_timestamp,
        enterprise_context=enterprise_context,
    )
    signal = normalize_entra_risk_event(payload)
    signal.provider_evidence = build_entra_provider_evidence(
        payload=payload,
        body=body,
        timestamp=x_zenthra_timestamp,
    )
    event, duplicate = persist_identity_event(db, signal)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return _response(event, duplicate=duplicate, elapsed_ms=elapsed_ms)


@router.post("/providers/{provider}/preflight", response_model=IdentityActionPreflightResponse)
def preflight_identity_provider_action(provider: str, payload: IdentityActionPreflightRequest):
    try:
        return action_preflight_payload(provider, payload.action_type, payload.risk_score)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/entities/{identity_id}/activity", response_model=IdentityActivityResponse)
def read_identity_activity(identity_id: str, limit: int = 10, db: Session = Depends(get_db)):
    return summarize_identity_activity(
        db,
        entity_id=identity_id if identity_id.startswith("user:") else f"user:{identity_id}",
        limit=limit,
    )


@router.get("/entities/{identity_id}/events", response_model=IdentityEventTimelineResponse)
def read_identity_events(identity_id: str, limit: int = 20, db: Session = Depends(get_db)):
    return list_identity_event_timeline(
        db,
        entity_id=identity_id if identity_id.startswith("user:") else f"user:{identity_id}",
        limit=limit,
    )


def _activity_factors(activity: dict[str, Any]) -> list[str]:
    factors = [
        f"identity_activity_events:{activity['event_count']}",
        f"identity_activity_max_risk:{activity['max_risk_score']}",
        f"identity_activity_risk_level:{activity['risk_level']}",
    ]
    factors.extend(f"identity_activity_event_type:{item}" for item in activity["event_types"])
    factors.extend(f"identity_activity_signal:{item}" for item in activity["signals"])
    factors.extend(f"identity_activity_provider:{item}" for item in activity["providers"])
    return factors


@router.post("/entities/{identity_id}/triage")
def triage_identity(
    identity_id: str,
    payload: IdentityTriageRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("identity:triage")),
):
    _ = enterprise_context
    entity_id = identity_id if identity_id.startswith("user:") else f"user:{identity_id}"
    activity = summarize_identity_activity(db, entity_id=entity_id, limit=10)
    if activity["event_count"] == 0:
        return {"status": "not_found", "entity_id": entity_id}

    provider = payload.provider or activity["recommended_provider"] or "custom"
    controls = {
        "dry_run": True,
        **payload.execution_controls,
        "identity_contract": "identity_activity.v1",
        "identity_provider": provider,
        "identity_activity": activity,
    }
    verdict = AutonomyService.issue_verdict(
        db,
        target=entity_id,
        risk_score=float(activity["max_risk_score"]),
        factors=_activity_factors(activity),
        execution_controls=controls,
    )
    response: dict[str, Any] = {
        "status": "ok",
        "activity": activity,
        "verdict": verdict,
    }
    if payload.execute:
        response["execution"] = AutonomyService.execute_verdict(
            db,
            verdict=verdict,
            human_approved=payload.human_approved,
            approval_evidence=payload.approval_evidence,
        )
    return response


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
def ingest_identity_event(
    payload: IdentitySignal,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("identity:triage")),
):
    _ = enterprise_context
    start = time.perf_counter()
    event, duplicate = persist_identity_event(db, payload)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return _response(event, duplicate=duplicate, elapsed_ms=elapsed_ms)


@router.post("/lifecycle")
def run_identity_lifecycle(
    payload: IdentityLifecycleRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("identity:execute")),
):
    _ = enterprise_context
    event, duplicate = persist_identity_event(db, payload.signal)
    controls = {
        "dry_run": True,
        **payload.execution_controls,
        "identity_contract": "identity_signal.v1",
        "identity_provider": payload.signal.provider,
    }
    verdict_response = AutonomyService.issue_verdict_from_threat_event(
        db,
        event_id=event.id,
        execution_controls=controls,
    )
    if verdict_response.get("status") == "not_found":
        return verdict_response

    execution_response = AutonomyService.execute_verdict(
        db,
        verdict=verdict_response["verdict"],
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )
    return {
        "status": "ok",
        "identity_event": _response(event, duplicate=duplicate, elapsed_ms=0),
        "verdict": verdict_response["verdict"],
        "execution": execution_response,
    }
