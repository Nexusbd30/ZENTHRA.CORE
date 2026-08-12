from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.ai_provider import AIProvider, LocalStubProvider, OllamaProvider, SafeAIProvider
from app.core.settings import settings
from app.ingestion import kafka_consumer
from app.schemas.threat_schema import ThreatCreate, ThreatUpdate
from app.services.threat_service import ThreatService


def test_ai_provider_parsing_fallback_and_ollama(monkeypatch):
    with pytest.raises(NotImplementedError):
        AIProvider().complete("system", "user")

    assert json.loads(LocalStubProvider().complete("system", "user"))["reasoning"] == "fallback-stub"

    assert SafeAIProvider.parse_json("") == {}
    assert SafeAIProvider.parse_json('{"a":1}') == {"a": 1}
    assert SafeAIProvider.parse_json('```json\n{"a":2}\n```') == {"a": 2}
    assert SafeAIProvider.parse_json('prefix {"a":3} suffix') == {"a": 3}
    assert SafeAIProvider.parse_json("prefix {bad} suffix") == {}
    assert SafeAIProvider.parse_json("no-json") == {}

    monkeypatch.setattr(settings, "AI_ENABLED", False)
    assert json.loads(SafeAIProvider().complete("system", "user"))["factors"] == ["stub"]

    class FailingProvider:
        def complete(self, system_prompt, user_prompt):
            raise RuntimeError("down")

    safe = SafeAIProvider()
    safe.provider = FailingProvider()
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    assert json.loads(safe.complete("system", "user"))["reasoning"] == "fallback-stub"

    calls = []

    class ResponseWithContent:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "  {\"ok\":true}  "}}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return ResponseWithContent()

    monkeypatch.setattr("app.core.ai_provider.requests.post", fake_post)
    monkeypatch.setattr(settings, "AI_MODEL", "model")
    monkeypatch.setattr(settings, "AI_BASE_URL", "http://ollama")
    monkeypatch.setattr(settings, "AI_TIMEOUT_SEC", 2.0)
    monkeypatch.setattr(settings, "AI_TEMPERATURE", 0.2)
    assert OllamaProvider().complete("sys", "usr") == '{"ok":true}'
    assert calls[0][0] == "http://ollama/api/chat"
    assert calls[0][1]["json"]["messages"][0]["content"] == "sys"

    class ResponseWithoutContent:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": ""}, "done": True}

    monkeypatch.setattr("app.core.ai_provider.requests.post", lambda *args, **kwargs: ResponseWithoutContent())
    assert json.loads(OllamaProvider().complete("sys", "usr"))["done"] is True


def test_kafka_status_helpers_and_consumer(monkeypatch):
    monkeypatch.setattr(settings, "KAFKA_INGESTION_ENABLED", False)
    monkeypatch.setattr(settings, "KAFKA_INGESTION_TOPICS", "vaelqorix.wazuh, vaelqorix.iam")
    disabled = kafka_consumer.run_kafka_consumer(on_event=lambda event: event, max_messages=1)
    assert disabled["status"] == "disabled"
    assert disabled["topics"] == ["vaelqorix.wazuh", "vaelqorix.iam"]

    monkeypatch.setattr(settings, "KAFKA_INGESTION_ENABLED", True)
    monkeypatch.setattr(
        kafka_consumer,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError("missing")),
    )
    unavailable = kafka_consumer.run_kafka_consumer(on_event=lambda event: event, max_messages=1)
    assert unavailable["status"] == "unavailable"

    assert kafka_consumer._message_value(SimpleNamespace(value=lambda: None)) == b"{}"
    assert kafka_consumer._message_value({"a": 1}) == '{"a": 1}'
    assert kafka_consumer._message_topic(SimpleNamespace(topic=lambda: ""), default="fallback") == "fallback"
    with pytest.raises(ValueError):
        kafka_consumer._decode_payload("[1,2,3]")
    assert kafka_consumer._adapter_from_payload({"adapter": "wazuh"}, "topic") == "wazuh"
    assert kafka_consumer._adapter_from_payload({}, "vaelqorix.wazuh") == "wazuh"
    assert kafka_consumer._adapter_from_payload({}, "unknown") == "raw"

    delivered = []
    batch = kafka_consumer.consume_message_batch(
        [
            SimpleNamespace(
                value=lambda: b'{"adapter":"iam","event_id":"e1","user":"alice","source_ip":"10.0.0.1"}',
                topic=lambda: "vaelqorix.iam",
            ),
            SimpleNamespace(value=lambda: b"[bad", topic=lambda: "vaelqorix.bad"),
        ],
        on_event=delivered.append,
    )
    assert batch["processed"] == 2
    assert batch["delivered"] == 1
    assert batch["failed"] == 1
    assert delivered[0]["source"] == "iam"

    class FakeMessage:
        def __init__(self, payload=None, *, error=False):
            self.payload = payload
            self._error = error

        def value(self):
            return self.payload

        def topic(self):
            return "vaelqorix.iam"

        def error(self):
            return self._error

    class FakeConsumer:
        instances = []

        def __init__(self, config):
            self.config = config
            self.messages = [
                FakeMessage(error=True),
                FakeMessage(b'{"event_id":"e2","user":"bob","source_ip":"10.0.0.2"}'),
                None,
            ]
            self.subscribed = []
            self.commits = 0
            self.closed = False
            FakeConsumer.instances.append(self)

        def subscribe(self, topics):
            self.subscribed = topics

        def poll(self, timeout):
            return self.messages.pop(0)

        def commit(self, *, message, asynchronous):
            self.commits += 1

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        kafka_consumer,
        "import_module",
        lambda name: SimpleNamespace(Consumer=FakeConsumer),
    )
    consumed = []
    result = kafka_consumer.run_kafka_consumer(on_event=consumed.append, max_messages=3)
    consumer = FakeConsumer.instances[-1]
    assert result["status"] == "ok"
    assert result["processed"] == 2
    assert result["delivered"] == 1
    assert result["failed"] == 1
    assert consumer.commits == 1
    assert consumer.closed is True
    assert consumed[0]["source"] == "iam"


def test_threat_service_crud_and_not_found_paths(db_session):
    service = ThreatService(db_session)
    created = service.create_threat(
        ThreatCreate(
            title="Service Threat",
            source="manual",
            description="created by service",
            level="medium",
            category="other",
            score=60,
            target_service="api",
        )
    )
    assert created.title == "Service Threat"

    all_items = service.get_all_threats(title="service", sort="created_at", order="asc")
    assert any(item.id == created.id for item in all_items)

    fetched = service.get_threat_by_id(created.id)
    assert fetched.id == created.id

    updated = service.update_threat(created.id, ThreatUpdate(title="Service Threat Updated"))
    assert updated.title == "Service Threat Updated"

    missing = uuid4()
    with pytest.raises(HTTPException) as missing_read:
        service.get_threat_by_id(missing)
    assert missing_read.value.status_code == 404

    with pytest.raises(HTTPException) as missing_update:
        service.update_threat(missing, ThreatUpdate(title="nope"))
    assert missing_update.value.status_code == 404

    assert service.delete_threat(created.id) is True
    with pytest.raises(HTTPException) as missing_delete:
        service.delete_threat(created.id)
    assert missing_delete.value.status_code == 404
