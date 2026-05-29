from __future__ import annotations

from typing import Protocol

from app.intelligence.contracts import KnowledgeDocument
from app.intelligence.knowledge_base import KNOWLEDGE_BASE


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


_DEFAULT_REPOSITORY = InMemoryKnowledgeRepository()


def get_knowledge_repository() -> KnowledgeRepository:
    return _DEFAULT_REPOSITORY
