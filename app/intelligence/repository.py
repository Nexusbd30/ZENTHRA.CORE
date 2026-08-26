from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from app.intelligence.contracts import KnowledgeDocument
from app.intelligence.knowledge_base import KNOWLEDGE_BASE
from app.models.knowledge_document import KnowledgeDocumentModel


class KnowledgeRepository(Protocol):
    provider: str

    def list_documents(self) -> tuple[KnowledgeDocument, ...]:
        raise NotImplementedError

    def search(
        self,
        *,
        query: str,
        domain: str,
        factors: list[str],
        limit: int = 3,
    ) -> tuple[KnowledgeDocument, ...]:
        raise NotImplementedError


def _tokens(values: list[str]) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        normalized = str(value or "").replace(":", " ").replace("_", " ").replace("-", " ").lower()
        tokens.update(part for part in normalized.split() if part)
        if value:
            tokens.add(str(value).strip().lower())
    return tokens


def _json_tuple(raw: str | None) -> tuple[str, ...]:
    try:
        decoded = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return ()
    if not isinstance(decoded, list):
        return ()
    return tuple(str(item) for item in decoded if str(item).strip())


def _json_dict(raw: str | None) -> dict[str, Any]:
    try:
        decoded = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _canonical_document_payload(document: KnowledgeDocument) -> dict[str, Any]:
    return {
        "doc_id": document.doc_id,
        "version": document.version,
        "title": document.title,
        "domain": document.domain,
        "tags": list(document.tags),
        "summary": document.summary,
        "recommended_actions": list(document.recommended_actions),
        "evidence_requirements": list(document.evidence_requirements),
        "source": document.source,
        "status": document.status,
        "metadata": document.metadata or {},
    }


def document_content_hash(document: KnowledgeDocument) -> str:
    payload = json.dumps(
        _canonical_document_payload(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def document_to_payload(document: KnowledgeDocument) -> dict[str, Any]:
    return {
        **_canonical_document_payload(document),
        "content_hash": document_content_hash(document),
        "contract": "vaelqorix.knowledge_document.v1",
    }


def model_to_document(row: KnowledgeDocumentModel) -> KnowledgeDocument:
    return KnowledgeDocument(
        doc_id=row.doc_id,
        version=int(row.version or 1),
        title=row.title,
        domain=row.domain,
        tags=_json_tuple(row.tags),
        summary=row.summary,
        recommended_actions=_json_tuple(row.recommended_actions),
        evidence_requirements=_json_tuple(row.evidence_requirements),
        source=row.source,
        status=row.status,
        metadata=_json_dict(row.metadata_json),
    )


def _score_document(document: KnowledgeDocument, *, domain: str, tokens: set[str]) -> int:
    score = 0
    if document.domain == domain:
        score += 5
    if document.domain == "generic":
        score += 1
    for tag in document.tags:
        tag_text = tag.lower()
        if tag_text in tokens:
            score += 4
        elif any(part in tokens for part in tag_text.replace("_", " ").split()):
            score += 2
    if any(action in tokens for action in document.recommended_actions):
        score += 2
    return score


class InMemoryKnowledgeRepository:
    provider = "in_memory"

    def __init__(self, documents: tuple[KnowledgeDocument, ...] = KNOWLEDGE_BASE):
        self._documents = documents

    def list_documents(self) -> tuple[KnowledgeDocument, ...]:
        return self._documents

    def search(
        self,
        *,
        query: str,
        domain: str,
        factors: list[str],
        limit: int = 3,
    ) -> tuple[KnowledgeDocument, ...]:
        normalized_domain = str(domain or "generic").strip().lower() or "generic"
        search_tokens = _tokens([query, normalized_domain, *factors])
        ranked = sorted(
            (
                (_score_document(document, domain=normalized_domain, tokens=search_tokens), document)
                for document in self._documents
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        return tuple(
            document for score, document in ranked if score > 0
        )[: max(1, min(limit, 5))]


class PersistentKnowledgeRepository:
    provider = "sqlalchemy"

    def __init__(self, db):
        self.db = db
        KnowledgeDocumentModel.__table__.create(bind=db.get_bind(), checkfirst=True)

    def list_documents(self) -> tuple[KnowledgeDocument, ...]:
        rows = (
            self.db.query(KnowledgeDocumentModel)
            .filter(KnowledgeDocumentModel.status == "active")
            .order_by(KnowledgeDocumentModel.domain.asc(), KnowledgeDocumentModel.doc_id.asc())
            .all()
        )
        return tuple(model_to_document(row) for row in rows)

    def list_versions(self, doc_id: str) -> tuple[KnowledgeDocument, ...]:
        rows = (
            self.db.query(KnowledgeDocumentModel)
            .filter(KnowledgeDocumentModel.doc_id == doc_id)
            .order_by(KnowledgeDocumentModel.version.desc())
            .all()
        )
        return tuple(model_to_document(row) for row in rows)

    def upsert_document(self, document: KnowledgeDocument) -> KnowledgeDocument:
        normalized = KnowledgeDocument(
            doc_id=str(document.doc_id).strip(),
            version=max(1, int(document.version or 1)),
            title=str(document.title).strip(),
            domain=str(document.domain or "generic").strip().lower() or "generic",
            tags=tuple(str(item).strip().lower() for item in document.tags if str(item).strip()),
            summary=str(document.summary).strip(),
            recommended_actions=tuple(
                str(item).strip() for item in document.recommended_actions if str(item).strip()
            ),
            evidence_requirements=tuple(
                str(item).strip() for item in document.evidence_requirements if str(item).strip()
            ),
            source=str(document.source or "operator").strip() or "operator",
            status=str(document.status or "active").strip().lower() or "active",
            metadata=document.metadata or {},
        )
        content_hash = document_content_hash(normalized)
        row = (
            self.db.query(KnowledgeDocumentModel)
            .filter(
                KnowledgeDocumentModel.doc_id == normalized.doc_id,
                KnowledgeDocumentModel.version == normalized.version,
            )
            .first()
        )
        now = datetime.utcnow()
        if row is None:
            row = KnowledgeDocumentModel(
                doc_id=normalized.doc_id,
                version=normalized.version,
                created_at=now,
            )
        row.title = normalized.title
        row.domain = normalized.domain
        row.tags = json.dumps(list(normalized.tags), sort_keys=True)
        row.summary = normalized.summary
        row.recommended_actions = json.dumps(list(normalized.recommended_actions), sort_keys=True)
        row.evidence_requirements = json.dumps(
            list(normalized.evidence_requirements), sort_keys=True
        )
        row.source = normalized.source
        row.status = normalized.status
        row.metadata_json = json.dumps(normalized.metadata or {}, sort_keys=True)
        row.content_hash = content_hash
        row.updated_at = now
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return model_to_document(row)

    def search(
        self,
        *,
        query: str,
        domain: str,
        factors: list[str],
        limit: int = 3,
    ) -> tuple[KnowledgeDocument, ...]:
        normalized_domain = str(domain or "generic").strip().lower() or "generic"
        search_tokens = _tokens([query, normalized_domain, *factors])
        documents = self.list_documents()
        ranked = sorted(
            (
                (_score_document(document, domain=normalized_domain, tokens=search_tokens), document)
                for document in documents
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        return tuple(
            document for score, document in ranked if score > 0
        )[: max(1, min(limit, 5))]


_DEFAULT_REPOSITORY = InMemoryKnowledgeRepository()


def get_knowledge_repository() -> KnowledgeRepository:
    return _DEFAULT_REPOSITORY


def get_persistent_knowledge_repository(db) -> PersistentKnowledgeRepository:
    return PersistentKnowledgeRepository(db)
