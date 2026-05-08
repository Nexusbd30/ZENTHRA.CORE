from __future__ import annotations

import json

from app.ingestion.kafka_consumer import consume_message_batch, normalize_kafka_message


class FakeMessage:
    def __init__(self, value: dict | str, topic: str = "zenthra.siem"):
        self._value = value
        self._topic = topic

    def value(self):
        if isinstance(self._value, str):
            return self._value
        return json.dumps(self._value).encode("utf-8")

    def topic(self):
        return self._topic


def test_kafka_message_normalizes_raw_event():
    result = normalize_kafka_message(
        FakeMessage(
            {
                "source": "siem",
                "alertname": "DatabaseExfiltration",
                "severity": "critical",
                "target": "db-prod-01",
                "source_ip": "198.51.100.9",
            },
            topic="zenthra.siem",
        )
    )

    assert result.status == "ok"
    assert result.adapter == "raw"
    assert result.normalized["title"] == "DatabaseExfiltration"
    assert result.normalized["level"].value == "critical"
    assert result.fingerprint


def test_kafka_message_uses_adapter_from_topic():
    result = normalize_kafka_message(
        FakeMessage(
            {
                "rule": {"id": "5710", "level": 10, "description": "Multiple failed ssh logins"},
                "agent": {"name": "linux-prod-01"},
                "data": {"srcip": "198.51.100.7"},
                "full_log": "sshd failed password burst",
            },
            topic="zenthra.wazuh",
        )
    )

    assert result.status == "ok"
    assert result.adapter == "wazuh"
    assert result.normalized["source"] == "wazuh/edr"
    assert result.normalized["target_service"] == "linux-prod-01"


def test_kafka_batch_delivers_only_valid_messages():
    delivered = []
    batch = consume_message_batch(
        [
            FakeMessage(
                {
                    "source": "iam",
                    "alertname": "ImpossibleTravel",
                    "severity": "high",
                    "target": "user@example.com",
                }
            ),
            FakeMessage("not-json"),
        ],
        on_event=delivered.append,
    )

    assert batch["processed"] == 2
    assert batch["delivered"] == 1
    assert batch["failed"] == 1
    assert delivered[0]["title"] == "ImpossibleTravel"
