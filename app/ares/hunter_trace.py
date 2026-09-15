from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.models.threat_event import ThreatEvent
from app.models.verdict import Verdict

HUNTER_TRACE_SCHEMA = "vaelqorix.ares.hunter_trace.v1"

PERSISTENCE_MARKERS = {
    "persistence",
    "scheduled_task",
    "startup_item",
    "new_service",
    "token_reuse",
    "refresh_token",
    "T1053",
    "T1543",
    "T1098",
}

LATERAL_MARKERS = {
    "lateral_movement",
    "remote_service",
    "admin_share",
    "runner_pivot",
    "T1021",
    "T1078",
}

EXFIL_MARKERS = {"exfiltration", "data_exfiltration", "large_egress", "T1041", "T1567"}


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _markers(event: ThreatEvent) -> set[str]:
    mitre_raw = _json_loads(event.mitre_tags, [])
    normalized_raw = _json_loads(event.normalized_payload or event.normalized, {})
    mitre: list[Any] = mitre_raw if isinstance(mitre_raw, list) else []
    normalized: dict[str, Any] = normalized_raw if isinstance(normalized_raw, dict) else {}
    signals_raw = normalized.get("signals")
    signals: list[Any] = signals_raw if isinstance(signals_raw, list) else []
    stage = normalized.get("kill_chain_stage") or normalized.get("stage") or ""
    return {
        str(item)
        for item in [
            event.event_type,
            event.source,
            stage,
            *mitre,
            *signals,
        ]
        if str(item).strip()
    }


def _event_trace(event: ThreatEvent) -> dict[str, Any]:
    normalized = _json_loads(event.normalized_payload or event.normalized, {})
    if not isinstance(normalized, dict):
        normalized = {}
    markers = _markers(event)
    finding_types = []
    if markers & PERSISTENCE_MARKERS:
        finding_types.append("persistence")
    if markers & LATERAL_MARKERS:
        finding_types.append("lateral_movement")
    if markers & EXFIL_MARKERS:
        finding_types.append("exfiltration")
    if int(event.severity or 0) >= 8:
        finding_types.append("high_severity")
    return {
        "event_id": event.id,
        "source_event_id": event.event_id,
        "source": event.source,
        "event_type": event.event_type,
        "entity_id": event.entity_id,
        "entity_type": event.entity_type,
        "severity": event.severity,
        "risk_score": round(float(event.risk_score or 0.0), 2),
        "occurred_at": _iso(event.occurred_at or event.timestamp),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "finding_types": list(dict.fromkeys(finding_types)),
        "summary": str(normalized.get("summary") or normalized.get("reason") or event.event_type),
    }


def _presence_state(events: list[dict[str, Any]], verdict: Verdict | None) -> str:
    if not events:
        return "unknown"
    if verdict and verdict.status in {"approved", "executed"}:
        return "contained_pending_verification"
    if any("persistence" in event["finding_types"] for event in events):
        return "persistent_presence_suspected"
    if any("lateral_movement" in event["finding_types"] for event in events):
        return "active_pivot_suspected"
    if max(int(event["severity"] or 0) for event in events) >= 8:
        return "active_presence_suspected"
    return "weak_or_historical_presence"


def _eviction_plan(
    *,
    target: str,
    events: list[dict[str, Any]],
    presence_state: str,
    controls: dict[str, Any],
) -> list[dict[str, Any]]:
    entity_types = {str(event["entity_type"]) for event in events if event["entity_type"]}
    has_identity = "user" in entity_types or target.startswith("user:")
    has_endpoint = "host" in entity_types or target.startswith(("host:", "endpoint:"))
    has_devsecops = any(
        "devsecops" in str(event["source"]) or event["entity_type"] in {"repository", "pipeline"}
        for event in events
    )
    plan = [
        {
            "step": "preserve_hunter_trace",
            "action": "snapshot_timeline_indicators_and_chain_of_custody",
            "target": target,
            "impact": "evidence only",
            "requires_confirmation": False,
        }
    ]
    if has_identity:
        plan.extend(
            [
                {
                    "step": "cut_suspicious_sessions",
                    "action": "revoke_sessions_and_refresh_tokens",
                    "target": target,
                    "impact": "forces re-authentication for suspected identity",
                    "requires_confirmation": True,
                },
                {
                    "step": "reset_identity_controls",
                    "action": "require_mfa_and_review_privileged_groups",
                    "target": target,
                    "impact": "reduces credential abuse path",
                    "requires_confirmation": True,
                },
            ]
        )
    if has_endpoint:
        plan.extend(
            [
                {
                    "step": "isolate_hunt_endpoint",
                    "action": "isolate_endpoint_if_trace_confirms_active_execution",
                    "target": target,
                    "impact": "contains endpoint communications",
                    "requires_confirmation": True,
                },
                {
                    "step": "remove_persistence",
                    "action": "disable_observed_persistence_mechanisms_inside_owned_host",
                    "target": target,
                    "impact": "removes suspected persistence points",
                    "requires_confirmation": True,
                },
            ]
        )
    if has_devsecops:
        plan.extend(
            [
                {
                    "step": "freeze_release_path",
                    "action": "block_deployment_and_quarantine_related_artifacts",
                    "target": target,
                    "impact": "prevents contaminated release propagation",
                    "requires_confirmation": True,
                },
                {
                    "step": "rotate_pipeline_access",
                    "action": "revoke_pipeline_tokens_and_rotate_exposed_secrets",
                    "target": target,
                    "impact": "removes CI/CD foothold",
                    "requires_confirmation": True,
                },
            ]
        )
    plan.append(
        {
            "step": "verify_eviction",
            "action": "confirm_no_new_events_sessions_persistence_or_pivots",
            "target": target,
            "impact": "verification only",
            "requires_confirmation": False,
            "success_criteria": [
                "no_new_high_severity_events",
                "no_active_suspicious_sessions",
                "no_observed_persistence",
                "no_lateral_movement_path",
            ],
        }
    )
    if controls.get("ctf_mode"):
        plan.append(
            {
                "step": "ctf_replay_pack",
                "action": "export_synthetic_defensive_trace_for_training",
                "target": target,
                "impact": "training artifact only",
                "requires_confirmation": False,
            }
        )
    if presence_state == "unknown":
        return plan[:1] + [plan[-1]]
    return plan


def build_hunter_trace(
    db: Session,
    *,
    target: str,
    verdict_id: str | None = None,
    limit: int = 100,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    verdict = db.get(Verdict, verdict_id) if verdict_id else None
    target_from_verdict = str(verdict.target) if verdict and verdict.target else target
    target = target or target_from_verdict
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(
                or_(
                    ThreatEvent.entity_id == target,
                    ThreatEvent.event_id == target,
                    ThreatEvent.id == target,
                )
            )
            .order_by(desc(ThreatEvent.occurred_at), desc(ThreatEvent.timestamp))
            .limit(max(1, min(limit, 500)))
        ).all()
    )
    events = [_event_trace(row) for row in rows]
    finding_counter: Counter[str] = Counter()
    for event in events:
        finding_counter.update(event["finding_types"])
    indicators = sorted(
        {
            str(value)
            for event in events
            for value in [event["src_ip"], event["dst_ip"], event["source"]]
            if str(value).strip()
        }
    )
    presence_state = _presence_state(events, verdict)
    eviction_plan = _eviction_plan(
        target=target,
        events=events,
        presence_state=presence_state,
        controls=controls,
    )
    confidence = 0.15
    if events:
        confidence += min(0.35, len(events) * 0.07)
        confidence += min(0.25, len(finding_counter) * 0.08)
        confidence += min(0.2, max(int(event["severity"] or 0) for event in events) / 50)
    confidence = round(min(0.98, confidence), 2)
    return {
        "schema": HUNTER_TRACE_SCHEMA,
        "mode": "defensive_hunt_inside_owned_environment",
        "target": target,
        "verdict_id": verdict_id or "",
        "event_count": len(events),
        "presence_state": presence_state,
        "confidence": confidence,
        "timeline": sorted(events, key=lambda item: str(item["occurred_at"] or "")),
        "hunt_findings": [
            {"type": key, "count": value}
            for key, value in sorted(finding_counter.items(), key=lambda item: item[1], reverse=True)
        ],
        "indicators": indicators,
        "eviction_plan": eviction_plan,
        "expulsion_readiness": "operator_gated" if events else "insufficient_evidence",
        "guardrails": [
            "owned_or_authorized_assets_only",
            "no_external_counter_intrusion",
            "human_approval_for_disruptive_steps",
            "kill_switch_and_internal_firewall_before_execution",
            "dry_run_recommended_for_ctf_and_training",
        ],
    }
