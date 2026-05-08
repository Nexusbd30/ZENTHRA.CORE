from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Callable, Iterable

from app.core.settings import settings
from app.ingestion.adapters import ADAPTERS, adapt_event
from app.ingestion.normalizer import normalize_event


@dataclass(frozen=True)
class KafkaIngestionResult:
    status: str
    adapter: str
    topic: str
    fingerprint: str
    normalized: dict[str, Any]
    error: str = ""


def kafka_status() -> dict[str, Any]:
    try:
        import_module("confluent_kafka")
        available = True
    except ImportError:
        available = False

    return {
        "enabled": bool(settings.KAFKA_INGESTION_ENABLED),
        "available": available,
        "bootstrap_servers": settings.KAFKA_BOOTSTRAP_SERVERS,
        "topics": [
            topic.strip()
            for topic in str(settings.KAFKA_INGESTION_TOPICS or "").split(",")
            if topic.strip()
        ],
        "group_id": settings.KAFKA_CONSUMER_GROUP_ID,
    }


def _message_value(message: Any) -> bytes | str:
    value = message.value() if callable(getattr(message, "value", None)) else message
    if value is None:
        return b"{}"
    if isinstance(value, bytes | str):
        return value
    return json.dumps(value)


def _message_topic(message: Any, default: str = "manual") -> str:
    topic = message.topic() if callable(getattr(message, "topic", None)) else default
    return str(topic or default)


def _decode_payload(value: bytes | str) -> dict[str, Any]:
    raw = value.decode("utf-8") if isinstance(value, bytes) else value
    decoded = json.loads(raw or "{}")
    if not isinstance(decoded, dict):
        raise ValueError("Kafka payload must decode to a JSON object")
    return decoded


def _adapter_from_payload(payload: dict[str, Any], topic: str) -> str:
    explicit = str(payload.get("adapter") or "").strip().lower()
    if explicit:
        return explicit
    topic_lower = topic.lower()
    for adapter in ADAPTERS:
        if adapter in topic_lower:
            return adapter
    return "raw"


def normalize_kafka_message(message: Any) -> KafkaIngestionResult:
    topic = _message_topic(message)
    try:
        payload = _decode_payload(_message_value(message))
        adapter = _adapter_from_payload(payload, topic)
        if adapter == "raw":
            normalized = normalize_event(payload)
        else:
            normalized = normalize_event(adapt_event(adapter, payload))
        return KafkaIngestionResult(
            status="ok",
            adapter=adapter,
            topic=topic,
            fingerprint=str(normalized["fingerprint"]),
            normalized=normalized,
        )
    except Exception as exc:  # noqa: BLE001
        return KafkaIngestionResult(
            status="error",
            adapter="unknown",
            topic=topic,
            fingerprint="",
            normalized={},
            error=str(exc),
        )


def consume_message_batch(
    messages: Iterable[Any],
    *,
    on_event: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    results = [normalize_kafka_message(message) for message in messages]
    delivered = 0
    for result in results:
        if result.status == "ok" and on_event is not None:
            on_event(result.normalized)
            delivered += 1

    return {
        "status": "ok",
        "processed": len(results),
        "delivered": delivered,
        "failed": sum(1 for result in results if result.status != "ok"),
        "items": [
            {
                "status": result.status,
                "adapter": result.adapter,
                "topic": result.topic,
                "fingerprint": result.fingerprint,
                "error": result.error,
            }
            for result in results
        ],
    }


def run_kafka_consumer(
    *,
    on_event: Callable[[dict[str, Any]], Any],
    max_messages: int | None = None,
) -> dict[str, Any]:
    if not settings.KAFKA_INGESTION_ENABLED:
        return {"status": "disabled", **kafka_status()}

    try:
        kafka_module = import_module("confluent_kafka")
    except ImportError:
        return {
            "status": "unavailable",
            "detail": "confluent-kafka is not installed",
            **kafka_status(),
        }

    consumer_cls = kafka_module.Consumer  # type: ignore[attr-defined]
    consumer = consumer_cls(
        {
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": settings.KAFKA_CONSUMER_GROUP_ID,
            "auto.offset.reset": settings.KAFKA_AUTO_OFFSET_RESET,
            "enable.auto.commit": False,
        }
    )
    topics = [
        topic.strip()
        for topic in str(settings.KAFKA_INGESTION_TOPICS or "").split(",")
        if topic.strip()
    ]
    consumer.subscribe(topics)

    processed = 0
    delivered = 0
    failed = 0
    try:
        while max_messages is None or processed < max_messages:
            message = consumer.poll(float(settings.KAFKA_POLL_TIMEOUT_SEC))
            if message is None:
                if max_messages is not None:
                    break
                continue
            if callable(getattr(message, "error", None)) and message.error():
                failed += 1
                processed += 1
                continue
            result = normalize_kafka_message(message)
            processed += 1
            if result.status == "ok":
                on_event(result.normalized)
                delivered += 1
                consumer.commit(message=message, asynchronous=False)
            else:
                failed += 1
    finally:
        consumer.close()

    return {
        "status": "ok",
        "processed": processed,
        "delivered": delivered,
        "failed": failed,
        **kafka_status(),
    }
