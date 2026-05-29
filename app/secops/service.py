from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.observability.metrics import record_soc_materialization
from app.identity.providers import list_provider_capability_payloads as list_identity_providers
from app.identity.service import summarize_identity_activity
from app.models.audit_record import AuditRecord
from app.models.execution_result import ExecutionResult
from app.models.threat_event import ThreatEvent
from app.models.verdict import Verdict
from app.secops.contracts import DevSecOpsControl, DevSecOpsSignal
from app.secops.providers import list_provider_capability_payloads as list_devsecops_providers

DEVSECOPS_MITRE_MAP: dict[str, list[str]] = {
    "sast_finding": ["T1190"],
    "dependency_vuln": ["T1190"],
    "secret_leak": ["T1552", "T1078"],
    "container_vuln": ["T1611"],
    "iac_misconfig": ["T1578"],
    "deployment_anomaly": ["T1078", "T1562"],
    "pipeline_identity_risk": ["T1078", "T1528"],
}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _status(ok: bool) -> str:
    return "ok" if ok else "attention"


def _devsecops_source(provider: str) -> str:
    return f"devsecops:{provider.strip().lower()}"


def _risk_level(score: float) -> str:
    if score >= 82:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _devsecops_signals(signal: DevSecOpsSignal) -> list[str]:
    signals: list[str] = []
    if signal.secret_detected or signal.event_type == "secret_leak":
        signals.append("secret_exposure")
    if signal.privileged_actor:
        signals.append("privileged_actor")
    if signal.production_target:
        signals.append("production_target")
    if signal.deployment_blocked:
        signals.append("deployment_blocked")
    if signal.critical_count:
        signals.append("critical_findings")
    if signal.high_count:
        signals.append("high_findings")
    if signal.cvss_score is not None and signal.cvss_score >= 9:
        signals.append("critical_cvss")
    if signal.actor_identity:
        signals.append("identity_actor_present")
    return sorted(set(signals))


def _devsecops_risk_score(signal: DevSecOpsSignal) -> float:
    score = float(signal.severity) * 7.0
    score += min(18.0, float(signal.critical_count) * 6.0)
    score += min(12.0, float(signal.high_count) * 3.0)
    score += min(8.0, float(signal.finding_count) * 0.75)
    if signal.cvss_score is not None:
        score += min(15.0, float(signal.cvss_score) * 1.5)
    if signal.secret_detected or signal.event_type == "secret_leak":
        score += 22.0
    if signal.privileged_actor:
        score += 12.0
    if signal.production_target:
        score += 12.0
    if signal.event_type in {"deployment_anomaly", "pipeline_identity_risk"}:
        score += 10.0
    if signal.deployment_blocked:
        score += 4.0
    return round(max(0.0, min(100.0, score)), 2)


def _devsecops_entity(signal: DevSecOpsSignal) -> tuple[str, str]:
    if signal.repository:
        return f"repository:{signal.repository}", "repository"
    if signal.pipeline_id:
        return f"pipeline:{signal.pipeline_id}", "pipeline"
    if signal.artifact:
        return f"artifact:{signal.artifact}", "artifact"
    if signal.actor_identity:
        return f"user:{signal.actor_identity}", "user"
    return f"devsecops:{signal.provider}", "service"


def _devsecops_context(
    signal: DevSecOpsSignal,
    *,
    event_type: str,
    risk_score: float,
    signals: list[str],
) -> dict[str, Any]:
    summary_parts = [
        f"{event_type} from {signal.provider}",
        f"risk={risk_score}",
    ]
    if signal.repository:
        summary_parts.append(f"repository={signal.repository}")
    if signal.pipeline_id:
        summary_parts.append(f"pipeline={signal.pipeline_id}")
    if signal.environment:
        summary_parts.append(f"environment={signal.environment}")
    if signals:
        summary_parts.append("signals=" + ",".join(signals))

    return {
        "pipeline": {
            "provider": signal.provider,
            "pipeline_id": signal.pipeline_id,
            "run_id": signal.run_id,
            "repository": signal.repository,
            "branch": signal.branch,
            "commit_sha": signal.commit_sha,
            "artifact": signal.artifact,
            "environment": signal.environment,
        },
        "actor": {
            "identity_id": signal.actor_identity,
            "privileged": signal.privileged_actor,
        },
        "finding": {
            "finding_count": signal.finding_count,
            "critical_count": signal.critical_count,
            "high_count": signal.high_count,
            "cvss_score": signal.cvss_score,
            "cve_ids": signal.cve_ids,
            "secret_detected": signal.secret_detected,
        },
        "controls": {
            "production_target": signal.production_target,
            "deployment_blocked": signal.deployment_blocked,
        },
        "signals": signals,
        "summary": "; ".join(summary_parts),
    }


def canonicalize_devsecops_signal(signal: DevSecOpsSignal) -> dict[str, Any]:
    event_type = str(signal.event_type).strip().lower()
    mitre_tags = sorted(set(DEVSECOPS_MITRE_MAP.get(event_type, ["T1190"])))
    risk_score = _devsecops_risk_score(signal)
    signals = _devsecops_signals(signal)
    entity_id, entity_type = _devsecops_entity(signal)
    devsecops_context = _devsecops_context(
        signal,
        event_type=event_type,
        risk_score=risk_score,
        signals=signals,
    )
    normalized = {
        "contract": "devsecops_signal.v1",
        "provider": signal.provider,
        "event_type": event_type,
        "pipeline_id": signal.pipeline_id,
        "run_id": signal.run_id,
        "repository": signal.repository,
        "branch": signal.branch,
        "commit_sha": signal.commit_sha,
        "artifact": signal.artifact,
        "environment": signal.environment,
        "actor_identity": signal.actor_identity,
        "risk_score": risk_score,
        "devsecops_context": devsecops_context,
    }
    return {
        "source": _devsecops_source(signal.provider),
        "event_id": signal.event_id,
        "occurred_at": signal.occurred_at,
        "event_type": event_type,
        "severity": signal.severity,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "mitre_tags": mitre_tags,
        "raw_payload": signal.raw_payload,
        "normalized_payload": normalized,
        "risk_score": risk_score,
        "signals": signals,
    }


def persist_devsecops_signal(db: Session, signal: DevSecOpsSignal) -> tuple[ThreatEvent, bool]:
    canonical = canonicalize_devsecops_signal(signal)
    existing = db.scalar(
        select(ThreatEvent).where(
            ThreatEvent.source == canonical["source"],
            ThreatEvent.event_id == canonical["event_id"],
        )
    )
    if existing:
        return existing, True

    now = datetime.now(UTC).replace(tzinfo=None)
    occurred_at = canonical["occurred_at"]
    if isinstance(occurred_at, datetime) and occurred_at.tzinfo is not None:
        occurred_at = occurred_at.astimezone(UTC).replace(tzinfo=None)

    event = ThreatEvent(
        source=canonical["source"],
        event_id=canonical["event_id"],
        occurred_at=occurred_at,
        ingested_at=now,
        timestamp=occurred_at or now,
        event_type=canonical["event_type"],
        severity=canonical["severity"],
        entity_id=canonical["entity_id"],
        entity_type=canonical["entity_type"],
        mitre_tags=_json(canonical["mitre_tags"]),
        raw_payload=_json(canonical["raw_payload"]),
        normalized=_json(canonical["normalized_payload"]),
        normalized_payload=_json(canonical["normalized_payload"]),
        risk_score=canonical["risk_score"],
        is_duplicate=False,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, False


def summarize_devsecops_signals(db: Session, *, limit: int = 50) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.source.like("devsecops:%"))
            .order_by(ThreatEvent.timestamp.desc())
            .limit(max(1, min(limit, 200)))
        ).all()
    )

    event_types: list[str] = []
    providers: list[str] = []
    repositories: list[str] = []
    environments: list[str] = []
    signals: list[str] = []
    max_risk_score = 0.0
    for row in rows:
        event_types.append(str(row.event_type))
        max_risk_score = max(max_risk_score, float(row.risk_score or 0.0))
        try:
            normalized = json.loads(row.normalized_payload or row.normalized or "{}")
        except json.JSONDecodeError:
            normalized = {}
        provider = normalized.get("provider")
        if provider:
            providers.append(str(provider))
        repository = normalized.get("repository")
        if repository:
            repositories.append(str(repository))
        environment = normalized.get("environment")
        if environment:
            environments.append(str(environment))
        context = normalized.get("devsecops_context")
        if isinstance(context, dict) and isinstance(context.get("signals"), list):
            signals.extend(str(item) for item in context["signals"] if item)

    return {
        "module": "secops",
        "count": len(rows),
        "max_risk_score": round(max_risk_score, 2),
        "risk_level": _risk_level(max_risk_score),
        "event_types": sorted(set(event_types)),
        "providers": sorted(set(providers)),
        "repositories": sorted(set(repositories)),
        "environments": sorted(set(environments)),
        "signals": sorted(set(signals)),
    }


def correlate_identity_devsecops(
    db: Session,
    *,
    actor_identity: str,
    limit: int = 50,
) -> dict[str, Any]:
    identity_entity_id = (
        actor_identity if actor_identity.startswith("user:") else f"user:{actor_identity}"
    )
    normalized_actor = identity_entity_id.removeprefix("user:")
    identity_activity = summarize_identity_activity(
        db,
        entity_id=identity_entity_id,
        limit=10,
    )
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.source.like("devsecops:%"))
            .order_by(ThreatEvent.timestamp.desc())
            .limit(max(1, min(limit, 200)))
        ).all()
    )

    matched_rows: list[ThreatEvent] = []
    event_types: list[str] = []
    repositories: list[str] = []
    environments: list[str] = []
    signals: list[str] = []
    max_devsecops_risk = 0.0
    for row in rows:
        try:
            normalized = json.loads(row.normalized_payload or row.normalized or "{}")
        except json.JSONDecodeError:
            normalized = {}
        if str(normalized.get("actor_identity") or "") != normalized_actor:
            continue
        matched_rows.append(row)
        event_types.append(str(row.event_type))
        max_devsecops_risk = max(max_devsecops_risk, float(row.risk_score or 0.0))
        repository = normalized.get("repository")
        if repository:
            repositories.append(str(repository))
        environment = normalized.get("environment")
        if environment:
            environments.append(str(environment))
        context = normalized.get("devsecops_context")
        if isinstance(context, dict) and isinstance(context.get("signals"), list):
            signals.extend(str(item) for item in context["signals"] if item)

    identity_score = float(identity_activity.get("max_risk_score") or 0.0)
    correlation_score = max(identity_score, max_devsecops_risk)
    if identity_activity.get("event_count", 0) and matched_rows:
        correlation_score += 10.0
    if "privileged_identity" in identity_activity.get("signals", []):
        correlation_score += 8.0
    if "secret_exposure" in signals:
        correlation_score += 8.0
    if "production_target" in signals:
        correlation_score += 6.0
    correlation_score = round(max(0.0, min(100.0, correlation_score)), 2)

    if correlation_score >= 90:
        recommended_action = "block_deployment"
    elif correlation_score >= 80:
        recommended_action = "quarantine_artifact"
    elif correlation_score >= 65:
        recommended_action = "revoke_pipeline_token"
    elif correlation_score >= 45:
        recommended_action = "require_release_approval"
    else:
        recommended_action = "observe"

    return {
        "module": "secops",
        "actor_identity": normalized_actor,
        "identity_entity_id": identity_entity_id,
        "correlated": bool(identity_activity.get("event_count", 0) and matched_rows),
        "correlation_score": correlation_score,
        "risk_level": _risk_level(correlation_score),
        "identity_activity": identity_activity,
        "devsecops_summary": {
            "count": len(matched_rows),
            "max_risk_score": round(max_devsecops_risk, 2),
            "event_types": sorted(set(event_types)),
            "repositories": sorted(set(repositories)),
            "environments": sorted(set(environments)),
        },
        "signals": sorted(set(signals)),
        "recommended_action": recommended_action,
    }


def _correlation_entity(correlation: dict[str, Any]) -> tuple[str, str]:
    repositories = correlation.get("devsecops_summary", {}).get("repositories", [])
    if isinstance(repositories, list) and repositories:
        return f"repository:{repositories[0]}", "repository"
    return str(correlation["identity_entity_id"]), "user"


def persist_identity_pipeline_correlation_event(
    db: Session,
    *,
    actor_identity: str,
    limit: int = 50,
) -> tuple[ThreatEvent | None, bool, dict[str, Any]]:
    correlation = correlate_identity_devsecops(db, actor_identity=actor_identity, limit=limit)
    if not correlation["correlated"]:
        return None, False, correlation

    entity_id, entity_type = _correlation_entity(correlation)
    event_id = f"identity-pipeline:{correlation['identity_entity_id']}"
    source = "secops:identity_pipeline_correlation"
    existing = db.scalar(
        select(ThreatEvent).where(
            ThreatEvent.source == source,
            ThreatEvent.event_id == event_id,
        )
    )
    if existing:
        return existing, True, correlation

    now = datetime.now(UTC).replace(tzinfo=None)
    signals = sorted(
        set(
            [
                "identity_pipeline_correlation",
                *[str(item) for item in correlation.get("signals", []) if item],
            ]
        )
    )
    normalized = {
        "contract": "devsecops_identity_pipeline_correlation.v1",
        "provider": "secops",
        "event_type": "identity_pipeline_correlation",
        "actor_identity": correlation["actor_identity"],
        "identity_entity_id": correlation["identity_entity_id"],
        "repository": (
            correlation.get("devsecops_summary", {}).get("repositories", [""])[0]
            if correlation.get("devsecops_summary", {}).get("repositories")
            else ""
        ),
        "environment": (
            correlation.get("devsecops_summary", {}).get("environments", [""])[0]
            if correlation.get("devsecops_summary", {}).get("environments")
            else ""
        ),
        "risk_score": correlation["correlation_score"],
        "correlation": correlation,
        "devsecops_context": {
            "pipeline": {
                "provider": "secops",
                "repository": (
                    correlation.get("devsecops_summary", {}).get("repositories", [""])[0]
                    if correlation.get("devsecops_summary", {}).get("repositories")
                    else ""
                ),
                "environment": (
                    correlation.get("devsecops_summary", {}).get("environments", [""])[0]
                    if correlation.get("devsecops_summary", {}).get("environments")
                    else ""
                ),
            },
            "actor": {
                "identity_id": correlation["actor_identity"],
                "privileged": "privileged_identity"
                in correlation.get("identity_activity", {}).get("signals", []),
            },
            "finding": {
                "secret_detected": "secret_exposure" in correlation.get("signals", []),
                "critical_count": 1 if correlation["risk_level"] == "critical" else 0,
                "high_count": 1 if correlation["risk_level"] in {"critical", "high"} else 0,
            },
            "controls": {
                "production_target": "production_target" in correlation.get("signals", []),
                "deployment_blocked": "deployment_blocked" in correlation.get("signals", []),
            },
            "signals": signals,
            "summary": (
                "identity_pipeline_correlation; "
                f"actor={correlation['actor_identity']}; "
                f"risk={correlation['correlation_score']}; "
                f"recommended_action={correlation['recommended_action']}"
            ),
        },
    }
    event = ThreatEvent(
        source=source,
        event_id=event_id,
        occurred_at=now,
        ingested_at=now,
        timestamp=now,
        event_type="identity_pipeline_correlation",
        severity=max(1, min(10, int(round(float(correlation["correlation_score"]) / 10.0)))),
        entity_id=entity_id,
        entity_type=entity_type,
        mitre_tags=_json(["T1078", "T1528", "T1552"]),
        raw_payload=_json({"correlation": correlation}),
        normalized=_json(normalized),
        normalized_payload=_json(normalized),
        risk_score=float(correlation["correlation_score"]),
        is_duplicate=False,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, False, correlation


def _recent_devsecops_actors(db: Session, *, limit: int = 100) -> list[str]:
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.source.like("devsecops:%"))
            .order_by(ThreatEvent.timestamp.desc())
            .limit(max(1, min(limit, 500)))
        ).all()
    )
    actors: list[str] = []
    for row in rows:
        try:
            normalized = json.loads(row.normalized_payload or row.normalized or "{}")
        except json.JSONDecodeError:
            normalized = {}
        actor = str(normalized.get("actor_identity") or "").strip()
        if actor:
            actors.append(actor)
    return list(dict.fromkeys(actors))


def materialize_identity_pipeline_correlations(
    db: Session,
    *,
    min_score: float = 60.0,
    limit: int = 100,
) -> dict[str, Any]:
    actors = _recent_devsecops_actors(db, limit=limit)
    items: list[dict[str, Any]] = []
    materialized = 0
    duplicates = 0
    skipped = 0
    threshold = max(0.0, min(100.0, float(min_score)))

    for actor in actors:
        correlation = correlate_identity_devsecops(db, actor_identity=actor, limit=limit)
        if not correlation.get("correlated"):
            skipped += 1
            items.append(
                {
                    "actor_identity": actor,
                    "status": "not_correlated",
                    "correlation_score": correlation.get("correlation_score", 0.0),
                    "recommended_action": correlation.get("recommended_action", "observe"),
                }
            )
            continue
        if float(correlation.get("correlation_score") or 0.0) < threshold:
            skipped += 1
            items.append(
                {
                    "actor_identity": actor,
                    "status": "below_threshold",
                    "correlation_score": correlation.get("correlation_score", 0.0),
                    "recommended_action": correlation.get("recommended_action", "observe"),
                }
            )
            continue
        event, duplicate, correlation = persist_identity_pipeline_correlation_event(
            db,
            actor_identity=actor,
            limit=limit,
        )
        if event is None:
            skipped += 1
            continue
        if duplicate:
            duplicates += 1
            status = "duplicate"
        else:
            materialized += 1
            status = "materialized"
        record_soc_materialization(event_type=SECURITY_ABUSE_EVENT_TYPE, status=status)
        items.append(
            {
                "actor_identity": actor,
                "status": status,
                "event_id": event.id,
                "source_event_id": event.event_id,
                "entity_id": event.entity_id,
                "risk_score": event.risk_score,
                "correlation_score": correlation.get("correlation_score", 0.0),
                "recommended_action": correlation.get("recommended_action", "observe"),
            }
        )

    return {
        "module": "secops",
        "scanned_actors": len(actors),
        "materialized": materialized,
        "duplicates": duplicates,
        "skipped": skipped,
        "min_score": threshold,
        "items": items,
    }


SECURITY_ABUSE_SOURCE = "secops:integration_security_abuse"
SECURITY_ABUSE_EVENT_TYPE = "integration_security_abuse"


def _security_event_group_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item.get("tenant_id") or "default"),
        str(item.get("provider") or "unknown"),
        str(item.get("reason") or "unknown"),
        str(item.get("client_ip") or "unknown"),
    )


def _security_abuse_event_id(group_key: tuple[str, str, str, str]) -> str:
    tenant, provider, reason, client_ip = group_key
    return f"integration-security-abuse:{tenant}:{provider}:{reason}:{client_ip}"


def _security_abuse_risk(reason: str, count: int) -> tuple[int, float, list[str]]:
    base = {
        "rate_limit_exceeded": 8,
        "replay_detected": 8,
        "invalid_signature": 7,
        "missing_signature": 6,
        "missing_timestamp": 6,
        "stale_timestamp": 6,
    }.get(reason, 6)
    severity = max(1, min(10, base + (1 if count >= 5 else 0)))
    risk_score = round(min(100.0, float(severity * 10) + min(20.0, float(count) * 4.0)), 2)
    signals = ["integration_security_abuse", f"reason:{reason}", "webhook_security_rejection"]
    if reason in {"rate_limit_exceeded", "replay_detected"}:
        signals.append("automated_abuse_pattern")
    return severity, risk_score, sorted(set(signals))


def _persist_security_abuse_event(
    db: Session,
    *,
    group_key: tuple[str, str, str, str],
    items: list[dict[str, Any]],
) -> tuple[ThreatEvent, bool]:
    event_id = _security_abuse_event_id(group_key)
    existing = db.scalar(
        select(ThreatEvent).where(
            ThreatEvent.source == SECURITY_ABUSE_SOURCE,
            ThreatEvent.event_id == event_id,
        )
    )
    if existing:
        return existing, True

    tenant, provider, reason, client_ip = group_key
    count = len(items)
    severity, risk_score, signals = _security_abuse_risk(reason, count)
    latest_timestamp = max(item["timestamp"] for item in items if item.get("timestamp"))
    if isinstance(latest_timestamp, datetime) and latest_timestamp.tzinfo is not None:
        latest_timestamp = latest_timestamp.astimezone(UTC).replace(tzinfo=None)
    now = datetime.now(UTC).replace(tzinfo=None)
    status_codes = sorted({int(item.get("status_code") or 0) for item in items})
    record_ids = [str(item.get("record_id") or "") for item in items if item.get("record_id")]
    source_event_ids = [
        str(item.get("source_event_id") or "") for item in items if item.get("source_event_id")
    ]
    payload_hashes = [
        str(item.get("payload_sha256") or "") for item in items if item.get("payload_sha256")
    ]
    normalized = {
        "contract": "secops_integration_security_abuse.v1",
        "provider": "secops",
        "event_type": SECURITY_ABUSE_EVENT_TYPE,
        "tenant_id": tenant,
        "integration_provider": provider,
        "reason": reason,
        "client_ip": client_ip,
        "rejection_count": count,
        "status_codes": status_codes,
        "audit_record_ids": record_ids,
        "source_event_ids": source_event_ids[:20],
        "payload_sha256": payload_hashes[:20],
        "secrets_exposed": False,
        "risk_score": risk_score,
        "devsecops_context": {
            "pipeline": {
                "provider": "secops",
                "environment": "integration_security",
                "repository": "",
                "pipeline_id": "",
            },
            "actor": {
                "identity_id": "",
                "privileged": False,
            },
            "finding": {
                "finding_count": count,
                "critical_count": 1 if risk_score >= 90 else 0,
                "high_count": 1 if risk_score >= 70 else 0,
                "secret_detected": False,
            },
            "controls": {
                "production_target": True,
                "deployment_blocked": False,
            },
            "signals": signals,
            "summary": (
                "integration_security_abuse; "
                f"tenant={tenant}; provider={provider}; reason={reason}; "
                f"client_ip={client_ip}; count={count}; risk={risk_score}"
            ),
        },
    }
    event = ThreatEvent(
        source=SECURITY_ABUSE_SOURCE,
        event_id=event_id,
        occurred_at=latest_timestamp,
        ingested_at=now,
        timestamp=latest_timestamp or now,
        event_type=SECURITY_ABUSE_EVENT_TYPE,
        severity=severity,
        entity_id=f"integration:{provider}:{tenant}",
        entity_type="integration",
        mitre_tags=_json(["T1190", "T1078", "T1110"]),
        raw_payload=_json(
            {
                "tenant_id": tenant,
                "provider": provider,
                "reason": reason,
                "client_ip": client_ip,
                "rejection_count": count,
                "audit_record_ids": record_ids,
                "secrets_exposed": False,
            }
        ),
        normalized=_json(normalized),
        normalized_payload=_json(normalized),
        src_ip="" if client_ip == "unknown" else client_ip,
        risk_score=risk_score,
        is_duplicate=False,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, False


def materialize_security_event_abuse(
    db: Session,
    *,
    min_count: int = 2,
    limit: int = 100,
) -> dict[str, Any]:
    threshold = max(1, min(100, int(min_count)))
    summary = summarize_security_events(db, limit=limit)
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for item in summary["items"]:
        groups.setdefault(_security_event_group_key(item), []).append(item)

    items: list[dict[str, Any]] = []
    materialized = 0
    duplicates = 0
    skipped = 0
    for group_key, grouped_items in groups.items():
        tenant, provider, reason, client_ip = group_key
        if len(grouped_items) < threshold:
            skipped += 1
            items.append(
                {
                    "tenant_id": tenant,
                    "provider": provider,
                    "reason": reason,
                    "client_ip": client_ip,
                    "count": len(grouped_items),
                    "status": "below_threshold",
                }
            )
            continue

        event, duplicate = _persist_security_abuse_event(
            db,
            group_key=group_key,
            items=grouped_items,
        )
        if duplicate:
            duplicates += 1
            status = "duplicate"
        else:
            materialized += 1
            status = "materialized"
        record_soc_materialization(event_type=SECURITY_ABUSE_EVENT_TYPE, status=status)
        items.append(
            {
                "tenant_id": tenant,
                "provider": provider,
                "reason": reason,
                "client_ip": client_ip,
                "count": len(grouped_items),
                "status": status,
                "event_id": event.id,
                "source_event_id": event.event_id,
                "entity_id": event.entity_id,
                "risk_score": event.risk_score,
            }
        )

    return {
        "module": "secops_security_events",
        "scanned_events": int(summary["count"]),
        "scanned_groups": len(groups),
        "materialized": materialized,
        "duplicates": duplicates,
        "skipped": skipped,
        "min_count": threshold,
        "items": items,
    }


def build_security_event_export_payload(
    db: Session,
    *,
    destination: str = "generic_webhook",
    export_format: str = "soc_case.v1",
    include_items: bool = True,
    limit: int = 100,
    reason: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    summary = summarize_security_events(
        db,
        reason=reason,
        tenant_id=tenant_id,
        limit=limit,
    )
    payload = {
        "contract": export_format,
        "case_type": "integration_security_abuse",
        "destination": destination,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "count": summary["count"],
            "by_reason": summary["by_reason"],
            "by_provider": summary["by_provider"],
            "by_tenant": summary["by_tenant"],
        },
        "filters": summary["filters"],
        "items": summary["items"] if include_items else [],
        "secrets_exposed": False,
    }
    return {
        "module": "secops_security_export",
        "contract": export_format,
        "destination": destination,
        "ready_to_send": False,
        "count": int(summary["count"]),
        "payload": payload,
        "secrets_exposed": False,
    }


def summarize_security_events(
    db: Session,
    *,
    event_type: str | None = None,
    reason: str | None = None,
    tenant_id: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    normalized_limit = max(1, min(limit, 200))
    query = (
        select(AuditRecord)
        .where(AuditRecord.event_type.like("%_webhook_rejected"))
        .order_by(AuditRecord.sequence_number.desc())
        .limit(normalized_limit)
    )
    if event_type:
        query = query.where(AuditRecord.event_type == event_type)
    if tenant_id:
        query = query.where(AuditRecord.tenant_id == tenant_id)

    rows = list(db.scalars(query).all())
    items: list[dict[str, Any]] = []
    by_reason: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    by_tenant: dict[str, int] = {}

    for row in rows:
        try:
            payload = json.loads(row.payload or row.result or "{}")
        except json.JSONDecodeError:
            payload = {}
        item_reason = str(payload.get("reason") or "")
        if reason and item_reason != reason:
            continue
        provider = str(payload.get("provider") or "")
        tenant = str(row.tenant_id or "default")
        by_reason[item_reason] = by_reason.get(item_reason, 0) + 1
        by_provider[provider] = by_provider.get(provider, 0) + 1
        by_tenant[tenant] = by_tenant.get(tenant, 0) + 1
        items.append(
            {
                "record_id": row.record_id,
                "timestamp": row.timestamp,
                "event_type": row.event_type,
                "reason": item_reason,
                "status_code": int(payload.get("status_code") or 0),
                "provider": provider,
                "source": str(payload.get("source") or ""),
                "source_event_id": str(payload.get("source_event_id") or ""),
                "tenant_id": tenant,
                "capability": str(row.capability or ""),
                "client_ip": str(payload.get("client_ip") or ""),
                "payload_sha256": str(payload.get("payload_sha256") or ""),
                "secrets_exposed": bool(payload.get("secrets_exposed", False)),
            }
        )

    return {
        "module": "secops_security_events",
        "count": len(items),
        "limit": normalized_limit,
        "filters": {
            "event_type": event_type or "",
            "reason": reason or "",
            "tenant_id": tenant_id or "",
        },
        "by_reason": by_reason,
        "by_provider": by_provider,
        "by_tenant": by_tenant,
        "items": items,
    }


def build_secops_posture(db: Session) -> dict:
    identity_events = (
        db.scalar(
            select(func.count())
            .select_from(ThreatEvent)
            .where(ThreatEvent.source.like("identity:%"))
        )
        or 0
    )
    devsecops_events = (
        db.scalar(
            select(func.count())
            .select_from(ThreatEvent)
            .where(ThreatEvent.source.like("devsecops:%"))
        )
        or 0
    )
    correlation_events = (
        db.scalar(
            select(func.count())
            .select_from(ThreatEvent)
            .where(ThreatEvent.source == "secops:identity_pipeline_correlation")
        )
        or 0
    )
    open_verdicts = (
        db.scalar(
            select(func.count())
            .select_from(Verdict)
            .where(Verdict.status.in_(["pending", "approved", "executing"]))
        )
        or 0
    )
    failed_executions = (
        db.scalar(
            select(func.count())
            .select_from(ExecutionResult)
            .where(ExecutionResult.status.in_(["failed", "rejected"]))
        )
        or 0
    )
    security_event_summary = summarize_security_events(db, limit=50)
    security_events = int(security_event_summary["count"])
    audit_records = db.scalar(select(func.count()).select_from(AuditRecord)) or 0
    identity_providers = list_identity_providers()
    devsecops_providers = list_devsecops_providers()
    identity_actions = sorted({action for provider in identity_providers for action in provider["actions"]})
    devsecops_actions = sorted(
        {action for provider in devsecops_providers for action in provider["actions"]}
    )

    controls = [
        DevSecOpsControl(
            key="identity_signal_ingestion",
            status=_status(identity_events > 0),
            owner="secops",
            detail="Identity telemetry is reaching the RedQueen/ARES pipeline"
            if identity_events
            else "No identity telemetry has been observed yet",
        ),
        DevSecOpsControl(
            key="devsecops_signal_ingestion",
            status=_status(devsecops_events > 0),
            owner="secops",
            detail="Pipeline and security-tool telemetry is reaching the RedQueen/ARES pipeline"
            if devsecops_events
            else "No DevSecOps telemetry has been observed yet",
        ),
        DevSecOpsControl(
            key="identity_pipeline_correlation",
            status=_status(correlation_events > 0),
            owner="secops",
            detail="Identity and pipeline signals are being materialized as actionable correlation events"
            if correlation_events
            else "No identity-pipeline correlation event has been materialized yet",
        ),
        DevSecOpsControl(
            key="redqueen_decision_gate",
            status="ok",
            owner="redqueen",
            detail="RedQueen emits signed verdicts and domain-aware actions",
        ),
        DevSecOpsControl(
            key="ares_execution_gate",
            status=_status(failed_executions == 0),
            owner="ares",
            detail="ARES validates signatures, policy, provider capabilities and approvals",
        ),
        DevSecOpsControl(
            key="audit_chain",
            status=_status(audit_records > 0),
            owner="platform",
            detail="Audit records are available for execution and governance evidence"
            if audit_records
            else "Audit chain has no records yet",
        ),
        DevSecOpsControl(
            key="security_event_monitoring",
            status="attention" if security_events else "ok",
            owner="soc",
            detail=(
                f"{security_events} integration security rejection events require SOC review"
                if security_events
                else "No integration security rejection events detected"
            ),
        ),
        DevSecOpsControl(
            key="identity_provider_preflight",
            status="ok",
            owner="secops",
            detail=(
                f"{len(identity_providers)} identity providers expose "
                f"{len(identity_actions)} defensive actions"
            ),
        ),
        DevSecOpsControl(
            key="devsecops_provider_preflight",
            status="ok",
            owner="secops",
            detail=(
                f"{len(devsecops_providers)} DevSecOps providers expose "
                f"{len(devsecops_actions)} defensive actions"
            ),
        ),
    ]

    attention = any(control.status != "ok" for control in controls)
    return {
        "module": "secops",
        "mode": "devsecops",
        "overall": "attention" if attention else "ok",
        "identity_events": int(identity_events),
        "devsecops_events": int(devsecops_events),
        "correlation_events": int(correlation_events),
        "security_events": security_events,
        "security_event_summary": {
            "by_reason": security_event_summary["by_reason"],
            "by_provider": security_event_summary["by_provider"],
            "by_tenant": security_event_summary["by_tenant"],
        },
        "open_verdicts": int(open_verdicts),
        "failed_executions": int(failed_executions),
        "audit_records": int(audit_records),
        "provider_registry": {
            "identity": {
                "provider_count": len(identity_providers),
                "actions": identity_actions,
            },
            "devsecops": {
                "provider_count": len(devsecops_providers),
                "actions": devsecops_actions,
            },
        },
        "controls": controls,
    }
