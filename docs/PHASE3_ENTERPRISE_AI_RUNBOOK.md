# Phase 3 Enterprise AI Runbook

Phase 3 hardens the backend AI layer into an enterprise control plane. The goal is not model novelty; the goal is persistent memory, governed LLM decisions, RedQueen/ARES traceability, evidence bundles, and readiness gates that frontend and SOC workflows can consume safely.

## Implemented Scope

1. Persistent AI memory through SQLAlchemy-backed knowledge documents.
2. Versioned knowledge document contract: `vaelqorix.knowledge_document.v1`.
3. Enterprise memory status contract: `vaelqorix.enterprise_memory.v1`.
4. LLM governance contract: `vaelqorix.llm_governance.v1`.
5. LLM decision trace contract: `vaelqorix.llm_decision_trace.v1`.
6. RedQueen/ARES contract tests to prevent current execution flow regressions.
7. Enterprise AI evaluation report over RedQueen/ARES feedback.
8. Enterprise AI readiness gate for controlled pilot decisions.
9. ARES AI evidence bundle for SOC/frontend consumption.
10. Enterprise AI contract registry for frontend and integration consumers.

## Stable Endpoints

Memory and knowledge:

- `GET /api/v1/secops/intelligence/status`
- `GET /api/v1/secops/intelligence/enterprise/status`
- `GET /api/v1/secops/intelligence/documents`
- `POST /api/v1/secops/intelligence/documents`

Enterprise AI governance:

- `GET /api/v1/secops/intelligence/enterprise/readiness`
- `GET /api/v1/secops/intelligence/enterprise/contracts`
- `GET /api/v1/redqueen/training/report`

ARES evidence:

- `GET /api/v1/ares/evidence/{verdict_id}`
- `GET /api/v1/ares/results/{verdict_id}`
- `GET /api/v1/ares/audit`
- `GET /api/v1/ares/audit/verify`

## Contract Registry

The contract registry is available at:

```http
GET /api/v1/secops/intelligence/enterprise/contracts
```

Current schemas:

- `vaelqorix.knowledge_document.v1`
- `vaelqorix.enterprise_memory.v1`
- `vaelqorix.llm_governance.v1`
- `redqueen.llm_decision.v1`
- `vaelqorix.ai_evaluation.v1`
- `vaelqorix.ares_ai_evidence_bundle.v1`
- `vaelqorix.enterprise_ai_readiness.v1`

The registry includes producer endpoints, consumer endpoints, required fields, evidence requirements, and frontend entrypoints. Frontend should treat this registry as the stable map for Enterprise AI surfaces.

## Readiness Gate

Enterprise AI readiness is available at:

```http
GET /api/v1/secops/intelligence/enterprise/readiness
```

The gate checks:

- Persistent memory is active.
- Knowledge documents are versioned.
- LLM governance is active.
- MCP action/tool policy remains part of the execution contract.
- RedQueen training report exposes enterprise AI evaluation metrics.
- RedQueen/ARES feedback samples exist.
- Evaluated LLM contracts are approved for ARES at the required threshold.
- Evaluated executions have traceable result hashes.

Expected overall values:

- `ready_for_controlled_pilot`
- `contract_ready_waiting_for_feedback`
- `attention_required`

## Evidence Bundle

ARES AI evidence is available at:

```http
GET /api/v1/ares/evidence/{verdict_id}
```

The bundle contract is:

```text
vaelqorix.ares_ai_evidence_bundle.v1
```

The bundle includes:

- ARES execution summaries.
- `intelligence_trace`.
- LLM contract.
- LLM governance.
- MCP action policy.
- MCP tool policy.
- RAG references.
- Verdict audit records.
- Audit-chain verification.
- `bundle_hash`.

SOC and frontend consumers should prefer this endpoint over assembling evidence from raw execution/audit endpoints.

## Operating Rules

- RedQueen remains the decision authority.
- ARES remains the only execution path.
- LLM output is never accepted without normalization and governance evidence.
- ARES evidence must include `intelligence_trace` for governed decisions.
- Real execution still depends on Phase 2 controls: provider readiness, preflight, `change_ticket`, ARES validation, and signed human approval when required.
- Readiness and contract registry are the first checks before enabling frontend enterprise workflows.

## Validation Gates

Run these before closing or merging Phase 3 work:

```powershell
ruff check app tests
mypy app
pytest -q
```

Current baseline after this phase block:

- Test suite: `242 passed`
- Coverage: `90%`
- Lint: passing
- Type check: passing

## Remaining Before Frontend

- Decide whether local SQL knowledge memory is enough for pilot, or move to pgvector, Qdrant, or Azure AI Search before production.
- Decide real LLM gateway/provider posture: local Ollama, Azure OpenAI gateway, or another governed provider.
- Add operator-facing policy copy for readiness states.
- Define frontend screens around contract registry, readiness, evidence bundle, and training report.
- Keep Phase 2 controls mandatory for all real provider execution.
