from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.detection.correlation import correlate_detections
from app.models.threat_event import ThreatEvent
from app.redqueen.anticipation import anticipate_attack_path
from app.redqueen.bridge_trace import build_bridge_trace
from app.redqueen.causal import build_causal_chain
from app.redqueen.strategic_anticipation import build_strategic_anticipation
from app.services.autonomy_service import AutonomyService

HIGH_CONFIDENCE_MITRE = {"T1078", "T1110", "T1003", "T1055", "T1059", "T1486", "T1041"}


def _json_loads(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _stage_for_event(event: ThreatEvent, normalized: dict[str, Any], mitre_tags: list[str]) -> str:
    explicit = normalized.get("kill_chain_stage") or normalized.get("stage")
    if explicit:
        return str(explicit)
    tags = {str(tag).upper() for tag in mitre_tags}
    event_type = str(event.event_type or "").lower()
    if tags & {"T1078", "T1110"} or "login" in event_type or "identity" in event.source:
        return "initial_access"
    if tags & {"T1059", "T1055"}:
        return "execution"
    if tags & {"T1003"} or "credential" in event_type:
        return "credential_access"
    if tags & {"T1041"} or "exfil" in event_type:
        return "exfiltration"
    if tags & {"T1486"} or "ransom" in event_type:
        return "impact"
    if "pipeline" in event_type or "deployment" in event_type:
        return "delivery"
    return "unknown"


def _event_payload(event: ThreatEvent) -> dict[str, Any]:
    mitre_tags = _json_loads(event.mitre_tags, [])
    if not isinstance(mitre_tags, list):
        mitre_tags = []
    normalized = _json_loads(event.normalized_payload or event.normalized, {})
    if not isinstance(normalized, dict):
        normalized = {}
    raw_payload = _json_loads(event.raw_payload, {})
    if not isinstance(raw_payload, dict):
        raw_payload = {}
    stage = _stage_for_event(event, normalized, mitre_tags)
    return {
        "id": event.id,
        "source_event_id": event.event_id,
        "source": event.source,
        "event_type": event.event_type,
        "entity_id": event.entity_id,
        "entity_type": event.entity_type,
        "severity": event.severity,
        "risk_score": round(float(event.risk_score or 0.0), 2),
        "stage": stage,
        "mitre_tags": [str(tag) for tag in mitre_tags],
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "geo_country": event.geo_country,
        "occurred_at": _iso(event.occurred_at or event.timestamp),
        "ingested_at": _iso(event.ingested_at),
        "signals": normalized.get("signals", []) if isinstance(normalized.get("signals"), list) else [],
        "summary": str(
            normalized.get("summary")
            or raw_payload.get("summary")
            or normalized.get("reason")
            or event.event_type
        ),
    }


def _risk_band(score: float) -> str:
    if score >= 85:
        return "confirmed_attack"
    if score >= 70:
        return "probable_attack"
    if score >= 45:
        return "suspicious_activity"
    if score >= 25:
        return "needs_human_review"
    return "false_positive_likely"


def _confidence(score: float, event_count: int) -> float:
    base = score / 100
    if event_count <= 1:
        base -= 0.12
    elif event_count >= 4:
        base += 0.08
    return round(max(0.05, min(0.99, base)), 2)


def _score_reality(events: list[dict[str, Any]]) -> tuple[float, list[str], list[str]]:
    if not events:
        return 0.0, ["no_events_available"], ["No hay eventos suficientes para decidir."]

    max_severity = max(int(event["severity"] or 0) for event in events)
    max_risk = max(float(event["risk_score"] or 0.0) for event in events)
    stages = sorted({str(event["stage"]) for event in events if event["stage"] != "unknown"})
    sources = sorted({str(event["source"]) for event in events if event["source"]})
    mitre_tags = sorted({tag.upper() for event in events for tag in event["mitre_tags"]})
    high_confidence_hits = sorted(set(mitre_tags) & HIGH_CONFIDENCE_MITRE)
    repeated_entities = [
        entity for entity, count in Counter(event["entity_id"] for event in events).items() if entity and count >= 2
    ]

    score = 0.0
    score += min(30.0, max_severity * 3.0)
    score += min(25.0, max_risk * 0.25)
    score += min(18.0, max(0, len(events) - 1) * 4.5)
    score += min(12.0, max(0, len(stages) - 1) * 6.0)
    score += min(8.0, max(0, len(sources) - 1) * 4.0)
    score += min(12.0, len(high_confidence_hits) * 4.0)
    if repeated_entities:
        score += 7.0
    if len(events) == 1 and max_severity <= 3 and max_risk < 35:
        score -= 18.0
    if not mitre_tags and len(events) <= 1:
        score -= 8.0

    score = round(max(0.0, min(100.0, score)), 2)
    evidence = [
        f"event_count:{len(events)}",
        f"max_severity:{max_severity}",
        f"max_event_risk:{max_risk}",
        f"stage_count:{len(stages)}",
        f"source_count:{len(sources)}",
    ]
    if stages:
        evidence.extend(f"kill_chain_stage:{stage}" for stage in stages)
    if high_confidence_hits:
        evidence.extend(f"high_confidence_mitre:{tag}" for tag in high_confidence_hits)
    if repeated_entities:
        evidence.append(f"repeated_entity_activity:{len(repeated_entities)}")

    false_positive_signals = []
    if len(events) == 1:
        false_positive_signals.append("single_event_no_corroboration")
    if max_severity <= 3 and max_risk < 35:
        false_positive_signals.append("low_severity_low_risk")
    if not mitre_tags:
        false_positive_signals.append("no_mitre_evidence")
    return score, evidence, false_positive_signals


class AttackAnalysisService:
    @staticmethod
    def list_analyses(db: Session, *, entity_id: str | None = None, limit: int = 100) -> dict:
        query = select(ThreatEvent).order_by(desc(ThreatEvent.occurred_at), desc(ThreatEvent.timestamp))
        if entity_id:
            query = query.where(ThreatEvent.entity_id == entity_id)
        rows = list(db.scalars(query.limit(max(1, min(limit, 500)))).all())
        events = [_event_payload(row) for row in rows]
        incidents = correlate_detections(
            [
                {
                    "entity_id": event["entity_id"] or "unknown",
                    "severity": event["severity"],
                    "kill_chain_stage": event["stage"],
                    "recommended_action": "soar_delegate",
                }
                for event in events
            ]
        )["incidents"]
        items = []
        by_entity: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            by_entity.setdefault(event["entity_id"] or "unknown", []).append(event)
        for incident in incidents:
            entity = str(incident["entity_id"])
            entity_events = by_entity.get(entity, [])
            score, evidence, false_positive_signals = _score_reality(entity_events)
            items.append(
                {
                    "entity_id": entity,
                    "event_count": len(entity_events),
                    "attack_reality_score": score,
                    "classification": _risk_band(score),
                    "confidence": _confidence(score, len(entity_events)),
                    "severity": incident["severity"],
                    "kill_chain_stages": incident["kill_chain_stages"],
                    "recommended_action": incident["recommended_action"],
                    "evidence": evidence,
                    "false_positive_signals": false_positive_signals,
                    "latest_event_at": entity_events[0]["occurred_at"] if entity_events else None,
                }
            )
        return {
            "module": "attack_analysis",
            "schema": "vaelqorix.attack_analysis.summary.v1",
            "count": len(items),
            "items": sorted(items, key=lambda item: item["attack_reality_score"], reverse=True),
        }

    @staticmethod
    def analyze_entity(db: Session, *, entity_id: str, limit: int = 100) -> dict:
        rows = list(
            db.scalars(
                select(ThreatEvent)
                .where(or_(ThreatEvent.entity_id == entity_id, ThreatEvent.event_id == entity_id, ThreatEvent.id == entity_id))
                .order_by(ThreatEvent.occurred_at, ThreatEvent.timestamp)
                .limit(max(1, min(limit, 500)))
            ).all()
        )
        events = [_event_payload(row) for row in rows]
        score, evidence, false_positive_signals = _score_reality(events)
        stages = sorted({str(event["stage"]) for event in events if event["stage"] != "unknown"})
        factors = list(dict.fromkeys([*evidence, *[f"false_positive_signal:{item}" for item in false_positive_signals]]))
        recommended_action = "observe"
        if score >= 85:
            recommended_action = "aggressive_containment"
        elif score >= 70:
            recommended_action = "soar_delegate"
        elif score >= 45:
            recommended_action = "observe"

        target = entity_id
        anticipation = anticipate_attack_path(
            target=target,
            risk_score=score,
            factors=factors,
            controls={"timeline": events, "attack_reality_score": score},
        )
        bridge_trace = build_bridge_trace(
            target=target,
            factors=factors,
            controls={"timeline": events, "attack_reality_score": score},
        )
        strategic = build_strategic_anticipation(
            target=target,
            risk_score=score,
            factors=factors,
            anticipation=anticipation,
            bridge_trace=bridge_trace,
            controls={"timeline": events, "attack_reality_score": score},
        )
        causal_chain = build_causal_chain(
            target=target,
            risk_score=score,
            action_type=recommended_action,
            perception={
                "entity_id": entity_id,
                "event_count": len(events),
                "kill_chain_stages": stages,
            },
            factors=factors,
            llm_reasoning="Attack reality analysis is based on correlated telemetry, stages, severity and false-positive signals.",
        )
        return {
            "module": "attack_analysis",
            "schema": "vaelqorix.attack_analysis.entity.v1",
            "entity_id": entity_id,
            "event_count": len(events),
            "attack_reality_score": score,
            "classification": _risk_band(score),
            "confidence": _confidence(score, len(events)),
            "recommended_action": recommended_action,
            "requires_human_review": score < 85 or bool(false_positive_signals),
            "evidence": evidence,
            "false_positive_signals": false_positive_signals,
            "kill_chain_stages": stages,
            "timeline": events,
            "causal_chain": causal_chain,
            "attack_anticipation": anticipation,
            "bridge_trace": bridge_trace,
            "strategic_anticipation": strategic,
        }

    @staticmethod
    def issue_verdict_from_analysis(
        db: Session,
        *,
        entity_id: str,
        execution_controls: dict | None = None,
    ) -> dict:
        analysis = AttackAnalysisService.analyze_entity(db, entity_id=entity_id)
        if not analysis["timeline"]:
            return {"status": "not_found", "entity_id": entity_id}
        factors = [
            *analysis["evidence"],
            f"attack_classification:{analysis['classification']}",
            f"attack_reality_score:{analysis['attack_reality_score']}",
        ]
        factors.extend(f"false_positive_signal:{item}" for item in analysis["false_positive_signals"])
        verdict = AutonomyService.issue_verdict(
            db,
            target=entity_id,
            risk_score=float(analysis["attack_reality_score"]),
            factors=list(dict.fromkeys(factors)),
            execution_controls={
                **(execution_controls or {}),
                "dry_run": True,
                "source": "attack-analysis",
                "attack_analysis": analysis,
                "perception": {
                    "entity_id": entity_id,
                    "event_count": analysis["event_count"],
                    "classification": analysis["classification"],
                },
            },
        )
        return {
            "status": "ok",
            "analysis": analysis,
            "verdict": verdict,
        }
