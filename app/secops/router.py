from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, status
from sqlalchemy.orm import Session

from app.core.enterprise_security import build_enterprise_readiness
from app.core.observability.metrics import record_soc_lifecycle
from app.core.security import require_admin_or_monitor_token, require_enterprise_capability
from app.db.session import get_db
from app.intelligence.contracts import KnowledgeDocument
from app.intelligence.readiness import build_enterprise_ai_readiness
from app.intelligence.repository import (
    document_to_payload,
    get_persistent_knowledge_repository,
)
from app.intelligence.status import build_enterprise_intelligence_status, build_intelligence_status
from app.models.threat_event import ThreatEvent
from app.secops.contracts import (
    DevSecOpsCorrelationLifecycleRequest,
    DevSecOpsCorrelationMaterializeRequest,
    DevSecOpsCorrelationMaterializeResponse,
    DevSecOpsIdentityCorrelationResponse,
    DevSecOpsLifecycleRequest,
    DevSecOpsProviderCapabilitiesResponse,
    DevSecOpsProviderPreflightRequest,
    DevSecOpsProviderPreflightResponse,
    DevSecOpsSignal,
    DevSecOpsSignalIngestResponse,
    DevSecOpsSignalSummaryResponse,
    IntelligenceStatusResponse,
    KnowledgeDocumentRequest,
    KnowledgeDocumentResponse,
    SecOpsExecutionPreflightRequest,
    SecOpsExecutionPreflightResponse,
    SecOpsPostureResponse,
    SecOpsStatusResponse,
    SecurityEventExportRequest,
    SecurityEventExportResponse,
    SecurityEventLifecycleRequest,
    SecurityEventMaterializeRequest,
    SecurityEventMaterializeResponse,
    SecurityEventSummaryResponse,
)
from app.secops.providers import (
    action_preflight_payload,
    list_provider_capability_payloads,
    provider_capability_payload,
)
from app.secops.readiness import (
    build_all_readiness,
    build_execution_preflight,
    build_secops_integration_readiness,
)
from app.secops.service import (
    build_secops_posture,
    build_security_event_export_payload,
    correlate_identity_devsecops,
    materialize_identity_pipeline_correlations,
    materialize_security_event_abuse,
    persist_devsecops_signal,
    persist_identity_pipeline_correlation_event,
    summarize_devsecops_signals,
    summarize_security_events,
)
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/secops",
    tags=["secops-devsecops"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


def _event_response(event: ThreatEvent, *, duplicate: bool, elapsed_ms: float) -> dict[str, Any]:
    try:
        mitre_tags = json.loads(event.mitre_tags or "[]")
    except json.JSONDecodeError:
        mitre_tags = []
    try:
        normalized = json.loads(event.normalized_payload or event.normalized or "{}")
    except json.JSONDecodeError:
        normalized = {}
    context = normalized.get("devsecops_context")
    signals = context.get("signals") if isinstance(context, dict) else []
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
        "mitre_tags": [str(item) for item in mitre_tags],
        "signals": [str(item) for item in signals] if isinstance(signals, list) else [],
        "is_duplicate": duplicate,
        "processing_time_ms": round(elapsed_ms, 2),
    }


@router.get("/status", response_model=SecOpsStatusResponse)
def secops_status():
    return {
        "module": "secops",
        "role": "devsecops_control_plane",
        "phase": "identity-and-pipeline-defense-core",
        "integrates": ["identity", "redqueen", "ares", "audit", "monitoring"],
        "devsecops_controls": [
            "identity_signal_ingestion",
            "devsecops_signal_ingestion",
            "identity_pipeline_correlation",
            "integration_security_abuse",
            "redqueen_decision_gate",
            "ares_execution_gate",
            "audit_chain",
            "provider_preflight",
        ],
    }


@router.get("/posture", response_model=SecOpsPostureResponse)
def secops_posture(db: Session = Depends(get_db)):
    return build_secops_posture(db)


@router.get("/intelligence/status", response_model=IntelligenceStatusResponse)
def secops_intelligence_status():
    return build_intelligence_status()


@router.get("/intelligence/enterprise/status", response_model=IntelligenceStatusResponse)
def secops_enterprise_intelligence_status(db: Session = Depends(get_db)):
    repository = get_persistent_knowledge_repository(db)
    return build_enterprise_intelligence_status(repository)


@router.get("/intelligence/enterprise/readiness")
def secops_enterprise_ai_readiness(db: Session = Depends(get_db)):
    repository = get_persistent_knowledge_repository(db)
    training_report = AutonomyService.get_training_report(db)
    return build_enterprise_ai_readiness(
        repository,
        ai_evaluation=training_report.get("ai_governance", {}),
    )


@router.get("/intelligence/documents", response_model=list[KnowledgeDocumentResponse])
def list_enterprise_knowledge_documents(db: Session = Depends(get_db)):
    repository = get_persistent_knowledge_repository(db)
    return [document_to_payload(document) for document in repository.list_documents()]


@router.post("/intelligence/documents", response_model=KnowledgeDocumentResponse)
def upsert_enterprise_knowledge_document(
    payload: KnowledgeDocumentRequest,
    db: Session = Depends(get_db),
):
    repository = get_persistent_knowledge_repository(db)
    document = KnowledgeDocument(
        doc_id=payload.doc_id,
        version=payload.version,
        title=payload.title,
        domain=payload.domain,
        tags=tuple(payload.tags),
        summary=payload.summary,
        recommended_actions=tuple(payload.recommended_actions),
        evidence_requirements=tuple(payload.evidence_requirements),
        source=payload.source,
        status=payload.status,
        metadata=payload.metadata,
    )
    return document_to_payload(repository.upsert_document(document))


@router.get("/security/events", response_model=SecurityEventSummaryResponse)
def secops_security_events(
    event_type: str | None = None,
    reason: str | None = None,
    tenant_id: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("soc:read")),
):
    _ = enterprise_context
    return summarize_security_events(
        db,
        event_type=event_type,
        reason=reason,
        tenant_id=tenant_id,
        limit=limit,
    )


@router.post("/security/events/export", response_model=SecurityEventExportResponse)
def export_secops_security_events(
    payload: SecurityEventExportRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("soc:read")),
):
    _ = enterprise_context
    return build_security_event_export_payload(
        db,
        destination=payload.destination,
        export_format=payload.format,
        include_items=payload.include_items,
        limit=payload.limit,
        reason=payload.reason,
        tenant_id=payload.tenant_id,
        send=payload.send,
    )


@router.post("/security/events/materialize", response_model=SecurityEventMaterializeResponse)
def materialize_secops_security_events(
    payload: SecurityEventMaterializeRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("soc:materialize")),
):
    _ = enterprise_context
    return materialize_security_event_abuse(
        db,
        min_count=payload.min_count,
        limit=payload.limit,
    )


@router.post("/security/events/{source_event_id}/lifecycle")
def run_secops_security_event_lifecycle(
    source_event_id: str,
    payload: SecurityEventLifecycleRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("soc:execute")),
):
    _ = enterprise_context
    event = (
        db.query(ThreatEvent)
        .filter_by(source="secops:integration_security_abuse", event_id=source_event_id)
        .first()
    )
    if event is None:
        record_soc_lifecycle(event_type="integration_security_abuse", status="not_found")
        return {
            "status": "not_found",
            "source_event_id": source_event_id,
        }

    controls = {
        "dry_run": True,
        **payload.execution_controls,
        "devsecops_contract": "secops_integration_security_abuse.v1",
        "devsecops_provider": "secops",
        "integration_security_abuse": True,
    }
    verdict_response = AutonomyService.issue_verdict_from_threat_event(
        db,
        event_id=event.id,
        execution_controls=controls,
    )
    if verdict_response.get("status") == "not_found":
        record_soc_lifecycle(event_type="integration_security_abuse", status="not_found")
        return verdict_response

    execution_response = AutonomyService.execute_verdict(
        db,
        verdict=verdict_response["verdict"],
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )
    record_soc_lifecycle(
        event_type="integration_security_abuse",
        status=str(execution_response.get("status") or "unknown"),
    )
    return {
        "status": "ok",
        "security_event": _event_response(event, duplicate=False, elapsed_ms=0),
        "verdict": verdict_response["verdict"],
        "execution": execution_response,
    }


@router.get("/enterprise/readiness")
def secops_enterprise_readiness(x_tenant_id: str | None = Header(default=None)):
    return build_enterprise_readiness(tenant_id=x_tenant_id)


@router.get("/integrations/readiness")
def secops_integrations_readiness():
    return build_all_readiness()


@router.get("/providers/github_actions/readiness")
def github_actions_readiness():
    return build_secops_integration_readiness("github_actions")


@router.get("/providers/{provider}/readiness")
def secops_provider_readiness(provider: str):
    return build_secops_integration_readiness(provider)


@router.get("/readiness/redis")
def redis_readiness():
    return build_secops_integration_readiness("redis")


@router.get("/readiness/soc-webhook")
def soc_webhook_readiness():
    return build_secops_integration_readiness("soc_webhook")


@router.get("/readiness/secrets")
def secret_backend_readiness():
    return build_secops_integration_readiness("secret_backend")


@router.get("/readiness/ingestion")
def siem_ingestion_readiness():
    return build_secops_integration_readiness("ingestion")


@router.post("/execution/preflight", response_model=SecOpsExecutionPreflightResponse)
def secops_execution_preflight(payload: SecOpsExecutionPreflightRequest):
    return build_execution_preflight(
        provider=payload.provider,
        action_type=payload.action_type,
        execution_controls=payload.execution_controls,
    )


@router.get("/providers", response_model=list[DevSecOpsProviderCapabilitiesResponse])
def list_devsecops_providers():
    return list_provider_capability_payloads()


@router.get("/providers/{provider}", response_model=DevSecOpsProviderCapabilitiesResponse)
def read_devsecops_provider(provider: str):
    return provider_capability_payload(provider)


@router.post(
    "/providers/{provider}/preflight",
    response_model=DevSecOpsProviderPreflightResponse,
)
def preflight_devsecops_provider_action(
    provider: str,
    payload: DevSecOpsProviderPreflightRequest,
):
    return action_preflight_payload(provider, payload.action_type)


@router.post(
    "/signals",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DevSecOpsSignalIngestResponse,
)
def ingest_devsecops_signal(
    payload: DevSecOpsSignal,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("devsecops:triage")),
):
    _ = enterprise_context
    start = time.perf_counter()
    event, duplicate = persist_devsecops_signal(db, payload)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return _event_response(event, duplicate=duplicate, elapsed_ms=elapsed_ms)


@router.get("/signals/summary", response_model=DevSecOpsSignalSummaryResponse)
def read_devsecops_signal_summary(limit: int = 50, db: Session = Depends(get_db)):
    return summarize_devsecops_signals(db, limit=limit)


@router.get(
    "/correlations/identity-pipeline/{actor_identity}",
    response_model=DevSecOpsIdentityCorrelationResponse,
)
def read_identity_pipeline_correlation(
    actor_identity: str,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    return correlate_identity_devsecops(db, actor_identity=actor_identity, limit=limit)


@router.post(
    "/correlations/identity-pipeline/materialize",
    response_model=DevSecOpsCorrelationMaterializeResponse,
)
def materialize_identity_pipeline_correlation_events(
    payload: DevSecOpsCorrelationMaterializeRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("devsecops:triage")),
):
    _ = enterprise_context
    return materialize_identity_pipeline_correlations(
        db,
        min_score=payload.min_score,
        limit=payload.limit,
    )


@router.post("/correlations/identity-pipeline/{actor_identity}/lifecycle")
def run_identity_pipeline_correlation_lifecycle(
    actor_identity: str,
    payload: DevSecOpsCorrelationLifecycleRequest,
    limit: int = 50,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("devsecops:execute")),
):
    _ = enterprise_context
    event, duplicate, correlation = persist_identity_pipeline_correlation_event(
        db,
        actor_identity=actor_identity,
        limit=limit,
    )
    if event is None:
        return {
            "status": "not_correlated",
            "correlation": correlation,
        }

    controls = {
        "dry_run": True,
        **payload.execution_controls,
        "devsecops_contract": "devsecops_identity_pipeline_correlation.v1",
        "devsecops_provider": "secops",
        "identity_pipeline_correlation": correlation,
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
        "correlation": correlation,
        "correlation_event": _event_response(event, duplicate=duplicate, elapsed_ms=0),
        "verdict": verdict_response["verdict"],
        "execution": execution_response,
    }


@router.post("/lifecycle")
def run_devsecops_lifecycle(
    payload: DevSecOpsLifecycleRequest,
    db: Session = Depends(get_db),
    enterprise_context: dict[str, Any] = Depends(require_enterprise_capability("devsecops:execute")),
):
    _ = enterprise_context
    event, duplicate = persist_devsecops_signal(db, payload.signal)
    controls = {
        "dry_run": True,
        **payload.execution_controls,
        "devsecops_contract": "devsecops_signal.v1",
        "devsecops_provider": payload.signal.provider,
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
        "devsecops_event": _event_response(event, duplicate=duplicate, elapsed_ms=0),
        "verdict": verdict_response["verdict"],
        "execution": execution_response,
    }
