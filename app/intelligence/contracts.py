from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeDocument:
    doc_id: str
    title: str
    domain: str
    tags: tuple[str, ...]
    summary: str
    recommended_actions: tuple[str, ...]
    evidence_requirements: tuple[str, ...]


@dataclass(frozen=True)
class RagContext:
    query: str
    domain: str
    references: tuple[KnowledgeDocument, ...]

