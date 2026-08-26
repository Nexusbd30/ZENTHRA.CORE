from __future__ import annotations

from app.intelligence.contracts import KnowledgeDocument
from app.intelligence.rag import rag_factors, retrieve_defensive_context
from app.intelligence.repository import InMemoryKnowledgeRepository


def test_rag_retrieves_devsecops_secret_exposure_playbook():
    context = retrieve_defensive_context(
        query="github actions secret_leak production",
        domain="devsecops",
        factors=[
            "devsecops_secret_detected:true",
            "devsecops_production_target:true",
            "event_type:secret_leak",
        ],
    )

    doc_ids = [document.doc_id for document in context.references]
    factors = rag_factors(context)

    assert "devsecops-secret-exposure" in doc_ids
    assert "rag_ref:devsecops-secret-exposure" in factors
    assert "rag_action:block_deployment" in factors


def test_rag_uses_replaceable_knowledge_repository():
    repository = InMemoryKnowledgeRepository(
        (
            KnowledgeDocument(
                doc_id="custom-identity-playbook",
                title="Custom identity playbook",
                domain="identity",
                tags=("custom_identity", "token_reuse"),
                summary="Custom repository document for identity defense.",
                recommended_actions=("revoke_session",),
                evidence_requirements=("custom_case",),
            ),
        )
    )

    context = retrieve_defensive_context(
        query="token_reuse custom_identity",
        domain="identity",
        factors=["custom_identity:true"],
        repository=repository,
    )

    assert [document.doc_id for document in context.references] == ["custom-identity-playbook"]
