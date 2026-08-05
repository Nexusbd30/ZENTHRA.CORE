# NexusOps AI Platform Architecture

Status: Development Folder Architecture v2.0

## Architectural Decision

NexusOps AI will evolve from the current ZENTHRA.CORE_SECURITY modular backend into a domain-oriented enterprise platform.

The migration strategy is incremental:

1. Preserve the working `app/` backend.
2. Introduce enterprise platform folders under `platform/`.
3. Add compatibility adapters from platform domains to existing implementation.
4. Move runtime code only when tests, Docker, imports and migrations are ready.

This avoids a high-risk folder move while giving the project the final enterprise shape.

## Target Root Structure

```text
apps/
platform/
domains/
packages/
infrastructure/
observability/
security/
tests/
docs/
scripts/
```

## Domain Ownership

| Domain | Responsibility | Existing backend mapping |
| --- | --- | --- |
| CortexFlow | Agent runtime and reasoning | `app.redqueen`, `app.ares`, `app.intelligence` |
| NexusFlow | Workflows and orchestration | `app.ares`, `app.services.autonomy_service` |
| BlackNode | Security and governance | `app.core`, `app.middlewares`, `app.models.audit_record`, `app.ares.approval` |
| NexusVault | Knowledge and RAG | `app.intelligence`, `app.db.vector`, `app.models.knowledge_document` |
| NexusAPI | Tools and integrations | `app.actions`, `app.identity`, `app.secops`, `app.ingestion` |
| DevSecOps domain | First commercial vertical | `app.secops`, `app.code_intelligence`, `app.actions.devsecops` |

## Runtime Rule

For now, production runtime remains `app.main:app`.

The platform folders are importable boundaries and documentation anchors. They should not become separate deployments until routing, state, tests and observability are explicitly migrated.

