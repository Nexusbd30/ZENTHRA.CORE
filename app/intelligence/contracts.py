from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class KnowledgeDocument:
    doc_id: str
    title: str
    domain: str
    tags: tuple[str, ...]
    summary: str
    recommended_actions: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    version: int = 1
    status: str = "active"
    source: str = "builtin"
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class RagContext:
    query: str
    domain: str
    references: tuple[KnowledgeDocument, ...]
