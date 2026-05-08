from __future__ import annotations

import pytest

from app.core.settings import settings
from app.db.vector import LocalVectorStore, cosine_similarity, embed_text


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def test_local_vector_store_searches_semantic_context():
    store = LocalVectorStore()
    store.upsert(
        collection="test-memory",
        record_id="incident-1",
        text="credential stuffing impossible travel privileged account",
        metadata={"target": "admin-portal"},
    )
    store.upsert(
        collection="test-memory",
        record_id="incident-2",
        text="database latency cpu saturation",
        metadata={"target": "db-prod"},
    )

    results = store.search(collection="test-memory", query="privileged credential anomaly")

    assert results[0]["id"] == "incident-1"
    assert results[0]["metadata"]["target"] == "admin-portal"
    assert results[0]["score"] > results[1]["score"]


def test_embedding_is_deterministic_and_normalized():
    left = embed_text("credential stuffing credential")
    right = embed_text("credential stuffing credential")

    assert left == right
    assert cosine_similarity(left, right) == 1.0


@pytest.mark.asyncio
async def test_redqueen_vector_memory_endpoints(test_client, monkeypatch):
    headers = autonomy_headers(monkeypatch)
    upsert = await test_client.post(
        "/api/v1/redqueen/vector/upsert",
        headers=headers,
        json={
            "collection": "api-memory",
            "record_id": "case-1",
            "text": "network isolate lateral movement ransomware",
            "metadata": {"target": "host-01"},
        },
    )
    assert upsert.status_code == 200, upsert.text

    search = await test_client.get(
        "/api/v1/redqueen/vector/search?collection=api-memory&q=lateral%20movement",
        headers=headers,
    )

    assert search.status_code == 200, search.text
    body = search.json()
    assert body["items"][0]["id"] == "case-1"
    assert body["items"][0]["metadata"]["target"] == "host-01"
