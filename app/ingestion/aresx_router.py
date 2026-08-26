from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.ingestion.adapters import ADAPTERS, adapt_event
from app.ingestion.normalizer import normalize_event
from app.models.threat_event import ThreatEvent

router = APIRouter(
    prefix="/api/v1/ingest",
    tags=["aresx-ingest"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)

MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class AresXIngestEventRequest(BaseModel):
    source: str = Field(..., min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class AresXIngestBatchRequest(BaseModel):
    events: list[AresXIngestEventRequest] = Field(default_factory=list, max_length=500)


def _json(value: Any) -> str:
    return json.dumps(
        value,
        default=lambda item: getattr(item, "value", str(item)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _first(payload: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for key in keys:
        current: Any = payload
        found = True
        for part in key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current not in (None, ""):
            return current
    return default


def _severity_1_to_10(normalized: dict[str, Any], raw: dict[str, Any]) -> int:
    raw_severity = _first(raw, ["severity", "magnitude", "rule.level", "level"])
    try:
        numeric = int(raw_severity)
        if 1 <= numeric <= 10:
            return numeric
        if 11 <= numeric <= 15:
            return 10
    except (TypeError, ValueError):
        pass

    score = normalized.get("score")
    try:
        if score is not None:
            return max(1, min(10, round(float(score) / 10)))
    except (TypeError, ValueError):
        pass

    level = str(getattr(normalized.get("level"), "value", normalized.get("level") or "")).lower()
    return {"critical": 10, "high": 8, "medium": 5, "low": 2}.get(level, 5)


def _event_type(normalized: dict[str, Any], raw: dict[str, Any]) -> str:
    explicit = _first(raw, ["event_type", "category", "rule.mitre.tactic.0", "alertDisplayName"])
    if explicit:
        return str(explicit).strip().lower().replace(" ", "_")
    category = str(getattr(normalized.get("category"), "value", normalized.get("category") or ""))
    if category:
        return category.strip().lower().replace(" ", "_")
    return "security_event"


def _event_id(source: str, normalized: dict[str, Any], raw: dict[str, Any]) -> str:
    explicit = _first(
        raw,
        [
            "event_id",
            "id",
            "offense_id",
            "rule.id",
            "DetectId",
            "detect_id",
            "eventRecordID",
            "uid",
        ],
    )
    if explicit:
        return str(explicit)
    fingerprint = str(normalized.get("fingerprint") or "")
    if fingerprint:
        return fingerprint
    digest = hashlib.sha256(_json({"source": source, "payload": raw}).encode("utf-8")).hexdigest()
    return digest[:32]


def _entity(normalized: dict[str, Any], raw: dict[str, Any]) -> tuple[str, str]:
    user = _first(raw, ["username", "user", "UserName", "data.srcuser", "actor.alternateId"])
    if user:
        return f"user:{user}", "user"

    host = _first(raw, ["agent.name", "host.name", "device.hostname", "computer", "target"])
    if host:
        return f"host:{host}", "host"

    target = normalized.get("target_service") or _first(raw, ["destination_ip", "dst_ip", "dst"])
    if target:
        entity_type = "network" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", str(target)) else "service"
        return f"{entity_type}:{target}", entity_type

    return "unknown:unknown", "unknown"


def _mitre_tags(normalized: dict[str, Any], raw: dict[str, Any]) -> list[str]:
    native = _first(raw, ["rule.mitre.id", "mitre_tags", "techniques", "Technique"], [])
    tags: list[str] = []
    if isinstance(native, list):
        tags.extend(str(item).upper() for item in native)
    elif native:
        tags.extend(MITRE_RE.findall(str(native).upper()))
    tags.extend(MITRE_RE.findall(_json({"raw": raw, "normalized": normalized}).upper()))
    return sorted(set(tags))


def _source_key(source: str) -> str:
    return source.strip().lower().split("/", 1)[0]


def _canonicalize(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    source_key = _source_key(source)
    adapted = adapt_event(source_key, payload) if source_key in ADAPTERS else {**payload, "source": source}
    normalized = normalize_event(adapted)
    entity_id, entity_type = _entity(normalized, payload)
    occurred_at_raw = _first(payload, ["occurred_at", "timestamp", "time", "startsAt"])
    occurred_at = None
    if isinstance(occurred_at_raw, str) and occurred_at_raw:
        try:
            occurred_at = datetime.fromisoformat(occurred_at_raw.replace("Z", "+00:00"))
        except ValueError:
            occurred_at = None

    return {
        "source": source_key,
        "event_id": _event_id(source_key, normalized, payload),
        "occurred_at": occurred_at,
        "event_type": _event_type(normalized, payload),
        "severity": _severity_1_to_10(normalized, payload),
        "entity_id": entity_id,
        "entity_type": entity_type,
        "mitre_tags": _mitre_tags(normalized, payload),
        "raw_payload": payload,
        "normalized_payload": normalized,
        "src_ip": str(_first(payload, ["src_ip", "source_ip", "data.srcip"], "") or ""),
        "dst_ip": str(_first(payload, ["dst_ip", "destination_ip", "dst"], "") or ""),
        "src_port": _first(payload, ["src_port", "source_port"]),
        "dst_port": _first(payload, ["dst_port", "destination_port", "port"]),
        "geo_country": str(_first(payload, ["geo_country", "geo.country"], "") or ""),
        "geo_city": str(_first(payload, ["geo_city", "geo.city"], "") or ""),
    }


def _persist_event(db: Session, canonical: dict[str, Any]) -> tuple[ThreatEvent, bool]:
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
        src_ip=canonical["src_ip"],
        dst_ip=canonical["dst_ip"],
        src_port=canonical["src_port"],
        dst_port=canonical["dst_port"],
        geo_country=canonical["geo_country"],
        geo_city=canonical["geo_city"],
        is_duplicate=False,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, False


def _response(event: ThreatEvent, *, is_duplicate: bool, elapsed_ms: float) -> dict[str, Any]:
    return {
        "status": "accepted",
        "aresx_id": event.id,
        "event_id": event.event_id,
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "entity_id": event.entity_id,
        "entity_type": event.entity_type,
        "mitre_tags": json.loads(event.mitre_tags or "[]"),
        "is_duplicate": is_duplicate,
        "ingested_at": event.ingested_at.isoformat() + "Z",
        "processing_time_ms": round(elapsed_ms, 2),
    }


@router.post("/event", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(payload: AresXIngestEventRequest, db: Session = Depends(get_db)):
    start = time.perf_counter()
    try:
        canonical = _canonicalize(payload.source, payload.payload)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Unsupported source '{payload.source}'") from exc
    event, duplicate = _persist_event(db, canonical)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return _response(event, is_duplicate=duplicate, elapsed_ms=elapsed_ms)


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
def ingest_batch(payload: AresXIngestBatchRequest, db: Session = Depends(get_db)):
    items = [ingest_event(item, db) for item in payload.events]
    return {
        "status": "accepted",
        "count": len(items),
        "accepted": sum(1 for item in items if not item["is_duplicate"]),
        "duplicates": sum(1 for item in items if item["is_duplicate"]),
        "items": items,
    }


@router.post("/webhook/{source}", status_code=status.HTTP_202_ACCEPTED)
def ingest_webhook(source: str, payload: dict[str, Any], db: Session = Depends(get_db)):
    return ingest_event(AresXIngestEventRequest(source=source, payload=payload), db)


@router.get("/sources")
def list_sources():
    return {
        "sources": sorted([*ADAPTERS.keys(), "manual", "prometheus"]),
        "adapters": sorted(ADAPTERS.keys()),
    }


@router.get("/stats")
def ingestion_stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(ThreatEvent.id))) or 0
    by_source = db.execute(
        select(ThreatEvent.source, func.count(ThreatEvent.id)).group_by(ThreatEvent.source)
    ).all()
    return {
        "window": "all",
        "total": int(total),
        "by_source": {str(source): int(count) for source, count in by_source},
    }
