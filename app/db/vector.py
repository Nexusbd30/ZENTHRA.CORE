from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

from app.core.settings import settings


@dataclass(frozen=True)
class VectorRecord:
    id: str
    vector: list[float]
    metadata: dict[str, Any] = field(default_factory=dict)


def embed_text(text: str, *, dimensions: int | None = None) -> list[float]:
    size = dimensions or int(settings.VECTOR_DIMENSIONS)
    vector = [0.0 for _ in range(size)]
    tokens = [token.strip().lower() for token in text.split() if token.strip()]
    if not tokens:
        return vector

    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % size
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[idx] += sign

    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [round(value / norm, 8) for value in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    return round(dot / (left_norm * right_norm), 6)


class LocalVectorStore:
    def __init__(self):
        self._collections: dict[str, dict[str, VectorRecord]] = {}

    def upsert(
        self,
        *,
        collection: str,
        record_id: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> VectorRecord:
        record = VectorRecord(
            id=record_id,
            vector=embed_text(text),
            metadata={**(metadata or {}), "text": text},
        )
        self._collections.setdefault(collection, {})[record_id] = record
        return record

    def search(self, *, collection: str, query: str, limit: int = 5) -> list[dict[str, Any]]:
        query_vector = embed_text(query)
        records = self._collections.get(collection, {})
        ranked = sorted(
            records.values(),
            key=lambda record: cosine_similarity(query_vector, record.vector),
            reverse=True,
        )
        return [
            {
                "id": record.id,
                "score": cosine_similarity(query_vector, record.vector),
                "metadata": record.metadata,
            }
            for record in ranked[: max(1, min(limit, 50))]
        ]

    def delete_collection(self, collection: str) -> bool:
        return self._collections.pop(collection, None) is not None

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(settings.VECTOR_STORE_ENABLED),
            "provider": settings.VECTOR_STORE_PROVIDER,
            "dimensions": settings.VECTOR_DIMENSIONS,
            "collections": {
                name: len(records)
                for name, records in sorted(self._collections.items())
            },
        }


vector_store = LocalVectorStore()
