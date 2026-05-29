from __future__ import annotations

from app.intelligence.contracts import RagContext
from app.intelligence.repository import KnowledgeRepository, get_knowledge_repository


def retrieve_defensive_context(
    *,
    query: str,
    domain: str,
    factors: list[str],
    limit: int = 3,
    repository: KnowledgeRepository | None = None,
) -> RagContext:
    normalized_domain = str(domain or "generic").strip().lower() or "generic"
    knowledge_repository = repository or get_knowledge_repository()
    references = knowledge_repository.search(
        query=query,
        domain=normalized_domain,
        factors=factors,
        limit=limit,
    )
    return RagContext(query=query, domain=normalized_domain, references=references)


def rag_factors(context: RagContext) -> list[str]:
    factors: list[str] = []
    for document in context.references:
        factors.append(f"rag_ref:{document.doc_id}")
        factors.append(f"rag_domain:{document.domain}")
        factors.extend(f"rag_action:{action}" for action in document.recommended_actions[:3])
        factors.extend(f"rag_evidence:{item}" for item in document.evidence_requirements[:3])
    return list(dict.fromkeys(factors))


def rag_payload(context: RagContext) -> dict:
    return {
        "query": context.query,
        "domain": context.domain,
        "references": [
            {
                "doc_id": document.doc_id,
                "title": document.title,
                "domain": document.domain,
                "tags": list(document.tags),
                "summary": document.summary,
                "recommended_actions": list(document.recommended_actions),
                "evidence_requirements": list(document.evidence_requirements),
            }
            for document in context.references
        ],
    }
