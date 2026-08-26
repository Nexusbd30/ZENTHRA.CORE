from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.intelligence.rag import retrieve_defensive_context
from app.intelligence.repository import get_persistent_knowledge_repository
from app.intelligence.status import build_enterprise_intelligence_status


class VaelqorixVaultKnowledgeRetriever:
    name = "VaelqorixVault"
    contract = "vaelqorix.vaelqorixvault.knowledge_retriever.v1"

    def build_status(self, db: Session) -> dict[str, Any]:
        repository = get_persistent_knowledge_repository(db)
        status = build_enterprise_intelligence_status(repository)
        return {
            "name": self.name,
            "contract": self.contract,
            "rag": status["rag"],
            "domains": status["domains"],
            "citation_required": True,
            "private_knowledge_policy": "answers_require_verifiable_sources",
        }

    def retrieve(
        self,
        *,
        query: str,
        domain: str,
        factors: list[str],
        limit: int = 3,
    ) -> dict[str, Any]:
        context = retrieve_defensive_context(
            query=query,
            domain=domain,
            factors=factors,
            limit=limit,
        )
        return {
            "query": context.query,
            "domain": context.domain,
            "references": [
                {
                    "doc_id": document.doc_id,
                    "title": document.title,
                    "source": document.source,
                    "version": document.version,
                }
                for document in context.references
            ],
            "citation_required": True,
        }


vaelqorixvault_retriever = VaelqorixVaultKnowledgeRetriever()

