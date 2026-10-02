from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

from app.core.settings import settings
from app.core.tenant_context import current_tenant
from app.db.session import SessionLocal
from app.models.runtime_state import VectorEntry


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


class SqlVectorStore:
    """Durable hashed-vector search; not an external embedding provider."""
    def __init__(self, session_factory=None):
        self.session_factory = session_factory

    def _session(self):
        db = (self.session_factory or SessionLocal)()
        db.info["tenant_id"] = current_tenant.get() or settings.DEFAULT_TENANT_ID
        return db

    def upsert(self, *, collection: str, record_id: str, text: str, metadata=None) -> VectorRecord:
        record = VectorRecord(record_id, embed_text(text), {**(metadata or {}), "text": text})
        with self._session() as db:
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
            insert = sqlite_insert if db.get_bind().dialect.name == "sqlite" else pg_insert
            statement = insert(VectorEntry).values(
                tenant_id=db.info["tenant_id"], collection=collection, record_id=record_id,
                vector_json=json.dumps(record.vector), metadata_json=json.dumps(record.metadata),
            )
            statement = statement.on_conflict_do_update(
                index_elements=["tenant_id", "collection", "record_id"],
                set_={"vector_json": statement.excluded.vector_json, "metadata_json": statement.excluded.metadata_json},
            )
            db.execute(statement)
            db.commit()
        return record

    def search(self, *, collection: str, query: str, limit: int = 5) -> list[dict[str, Any]]:
        vector = embed_text(query)
        with self._session() as db:
            rows = db.query(VectorEntry).filter(VectorEntry.collection == collection).all()
            ranked = sorted(
                ({"id": row.record_id, "score": cosine_similarity(vector, json.loads(row.vector_json)),
                  "metadata": json.loads(row.metadata_json)} for row in rows),
                key=lambda item: item["score"], reverse=True,
            )
        return ranked[:max(1, min(limit, 50))]

    def delete_collection(self, collection: str) -> bool:
        with self._session() as db:
            count = db.query(VectorEntry).filter(VectorEntry.collection == collection).delete()
            db.commit()
            return bool(count)

    def status(self) -> dict[str, Any]:
        from sqlalchemy import func
        with self._session() as db:
            collections = dict(db.query(VectorEntry.collection, func.count(VectorEntry.id)).group_by(VectorEntry.collection).all())
        return {"enabled": bool(settings.VECTOR_STORE_ENABLED), "provider": "sql_local",
                "persistent": True, "embedding": "hashed_tokens", "dimensions": settings.VECTOR_DIMENSIONS,
                "collections": collections}


vector_store = SqlVectorStore()
